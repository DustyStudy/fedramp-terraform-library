"""
Audits how RDS and Aurora databases can be reached and who can log in to
them, on a schedule, and publishes a summary to SNS. Detective only -
never changes a database, parameter group, security group or policy,
since a surprise reboot or a locked-out application is its own incident.

Five checks, all from the AWS control plane (no database connection):

1. Public access. A publicly accessible instance whose security groups
   allow 0.0.0.0/0 or ::/0 on the database port is reachable from the
   internet. Publicly accessible with closed security groups is reported
   too: one rule change away.
2. Master credentials. A master password not managed by RDS in Secrets
   Manager is a static credential for the most privileged database user
   (rds_superuser on PostgreSQL) that nothing rotates.
3. IAM database authentication off (MySQL, MariaDB, PostgreSQL and their
   Aurora versions). Applications then log in with shared static
   passwords rather than per-principal, short-lived tokens.
4. Transport encryption not enforced in the parameter group
   (rds.force_ssl on PostgreSQL and SQL Server, require_secure_transport
   on MySQL and MariaDB).
5. IAM policies granting rds-db:connect as any database user, or as a
   database's master user. With IAM authentication that means logging in
   as whoever the caller likes, including the superuser.

What database roles hold inside the engine (SELECT versus superuser,
default_transaction_read_only) needs a database connection; see
sql/audit_postgres_roles.sql next to this module.

Set MEMBER_ROLE_NAME to scan every active account in the organization by
assuming that role in each; leave it empty to scan only this account.

Env vars:
  SNS_TOPIC_ARN     - where to send the audit summary
  MEMBER_ROLE_NAME  - role to assume in member accounts ("" = this account
                      only)
  REGIONS           - comma-separated regions for RDS (default: the
                      Lambda's own region). IAM is global.
"""

import fnmatch
import json
import logging
import os
import urllib.parse

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

sts = boto3.client("sts")
organizations = boto3.client("organizations")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
MEMBER_ROLE_NAME = os.environ.get("MEMBER_ROLE_NAME", "").strip()
REGIONS = [r.strip() for r in os.environ.get("REGIONS", "").split(",") if r.strip()]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# describe_db_instances and describe_db_clusters also return DocumentDB
# and Neptune, which this audit doesn't cover.
RDS_ENGINES = ("aurora", "mysql", "mariadb", "postgres", "sqlserver", "oracle", "db2", "custom-")
IAM_AUTH_ENGINES = ("aurora", "mysql", "mariadb", "postgres")
# Parameter that forces TLS, per engine prefix, and the values that mean on.
TLS_PARAMETERS = [
    (("aurora-postgresql", "postgres", "sqlserver"), "rds.force_ssl", {"1"}),
    (("aurora-mysql", "aurora", "mysql", "mariadb"), "require_secure_transport", {"1", "on"}),
]
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _finding(severity, check, account_id, resource, detail):
    return {"severity": severity, "check": check, "account": account_id, "resource": resource, "detail": detail}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_rds(engine):
    return (engine or "").startswith(RDS_ENGINES)


def _tls_parameter(engine):
    for prefixes, name, on_values in TLS_PARAMETERS:
        if engine.startswith(prefixes):
            return name, on_values
    return None


# --- checks 1-4: databases --------------------------------------------------


def open_to_internet(security_groups, port):
    """Security group IDs with a rule admitting 0.0.0.0/0 or ::/0 on port."""
    open_ids = []
    for group in security_groups:
        for rule in group.get("IpPermissions", []):
            all_traffic = rule.get("IpProtocol") == "-1"
            in_range = rule.get("FromPort", -1) <= port <= rule.get("ToPort", -1)
            if not (all_traffic or in_range):
                continue
            cidrs = {r.get("CidrIp") for r in rule.get("IpRanges", [])}
            cidrs |= {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
            if cidrs & OPEN_CIDRS:
                open_ids.append(group["GroupId"])
                break
    return open_ids


def check_public_access(instance, security_groups, account_id):
    if not instance.get("PubliclyAccessible"):
        return []
    arn = instance["DBInstanceArn"]
    port = (instance.get("Endpoint") or {}).get("Port") or instance.get("DbInstancePort")
    open_ids = open_to_internet(security_groups, port) if port else []
    if open_ids:
        detail = f"is publicly accessible and {', '.join(open_ids)} admit(s) the internet on port {port}"
        return [_finding("CRITICAL", "public-access", account_id, arn, detail)]
    detail = "is publicly accessible (has a public IP); only its security groups keep the internet out"
    return [_finding("HIGH", "public-access", account_id, arn, detail)]


def check_credentials(database, arn, account_id):
    """Checks 2 and 3 for a standalone instance or a cluster (instances in
    a cluster take these settings from it)."""
    findings = []
    if not database.get("MasterUserSecret"):
        detail = (
            f"master user '{database.get('MasterUsername')}' has a password RDS doesn't manage in Secrets Manager: "
            "a static credential for the most privileged database user that nothing rotates"
        )
        findings.append(_finding("MEDIUM", "master-credentials", account_id, arn, detail))
    if database["Engine"].startswith(IAM_AUTH_ENGINES) and not database.get("IAMDatabaseAuthenticationEnabled"):
        detail = "IAM database authentication is off, so applications log in with static passwords"
        findings.append(_finding("LOW", "iam-auth", account_id, arn, detail))
    return findings


def check_transport(engine, parameters, group_name, arn, account_id):
    """parameters: {name: value} for the database's parameter group."""
    tls = _tls_parameter(engine)
    if not tls:
        return []
    name, on_values = tls
    value = parameters.get(name)
    if value is not None and value.lower() in on_values:
        return []
    shown = "not set (engine default)" if value is None else f"'{value}'"
    detail = f"parameter group {group_name} leaves {name} {shown}, so clients may connect without TLS"
    return [_finding("MEDIUM", "transport", account_id, arn, detail)]


# --- check 5: IAM rds-db:connect scope ----------------------------------------


def _wild(text):
    return "*" in text or "?" in text


def _grants_connect(action):
    action = action.lower()
    return action.startswith("rds-db:") and fnmatch.fnmatchcase("rds-db:connect", action)


def connect_scope_problem(resource, masters):
    """Why an rds-db:connect grant on resource is too broad, or None.

    masters: [(resource_id, username)] for the account's databases."""
    if resource == "*":
        return "HIGH", "can connect to any database as any user, including the master user"
    parts = resource.split(":", 5)
    if len(parts) < 6 or not fnmatch.fnmatchcase("rds-db", parts[2]):
        return None
    rest = parts[5]
    if not rest.startswith("dbuser:"):
        if fnmatch.fnmatchcase("dbuser:db-X/user", rest):
            return "HIGH", f"'{resource}' lets it connect as any database user"
        return None
    resource_id, _, user = rest[len("dbuser:"):].partition("/")
    if user in ("", "*"):
        return "HIGH", f"'{resource}' lets it connect as any database user, including the master user"
    for master_resource_id, master_user in masters:
        if fnmatch.fnmatchcase(master_resource_id, resource_id) and fnmatch.fnmatchcase(master_user, user):
            return "HIGH", f"'{resource}' lets it connect as master user '{master_user}' of {master_resource_id}"
    if _wild(user):
        return "MEDIUM", f"'{resource}' matches several database users; review it by hand"
    return None


def _document(policy):
    if isinstance(policy, str):
        policy = json.loads(urllib.parse.unquote(policy))
    return policy or {}


def check_policy_document(document, resource, masters, account_id):
    findings = []
    for statement in _as_list(_document(document).get("Statement")):
        if statement.get("Effect") != "Allow" or "Action" not in statement or "Resource" not in statement:
            continue
        if not any(_grants_connect(a) for a in _as_list(statement["Action"])):
            continue
        for target in _as_list(statement["Resource"]):
            problem = connect_scope_problem(target, masters)
            if problem:
                findings.append(_finding(problem[0], "db-connect", account_id, resource, problem[1]))
    return findings


def check_iam(details, masters, account_id):
    """Findings from iam:GetAccountAuthorizationDetails output."""
    findings = []
    principals = (
        [(u["Arn"], u.get("UserPolicyList", [])) for u in details["users"]]
        + [(g["Arn"], g.get("GroupPolicyList", [])) for g in details["groups"]]
        + [(r["Arn"], r.get("RolePolicyList", [])) for r in details["roles"] if not r.get("Path", "/").startswith("/aws-service-role/")]
    )
    for arn, inline in principals:
        for policy in inline:
            resource = f"{arn} (inline policy {policy['PolicyName']})"
            findings += check_policy_document(policy["PolicyDocument"], resource, masters, account_id)
    for policy in details["policies"]:
        if not policy.get("AttachmentCount"):
            continue
        versions = [v for v in policy.get("PolicyVersionList", []) if v.get("IsDefaultVersion")]
        for version in versions:
            resource = f"{policy['Arn']} (attached to {policy['AttachmentCount']})"
            findings += check_policy_document(version["Document"], resource, masters, account_id)
    return findings


# --- collection -------------------------------------------------------------


def _paginate(client, operation, result_key, **kwargs):
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(result_key, [])


def _authorization_details(iam):
    details = {"users": [], "groups": [], "roles": [], "policies": []}
    pages = iam.get_paginator("get_account_authorization_details").paginate(
        Filter=["User", "Group", "Role", "LocalManagedPolicy"]
    )
    for page in pages:
        details["users"] += page.get("UserDetailList", [])
        details["groups"] += page.get("GroupDetailList", [])
        details["roles"] += page.get("RoleDetailList", [])
        details["policies"] += page.get("Policies", [])
    return details


def audit_region(account_id, rds, ec2):
    """Checks 1-4 in one region. Returns (findings, masters)."""
    findings, masters = [], []
    parameter_cache = {}

    def parameters(kind, name):
        if (kind, name) not in parameter_cache:
            if kind == "cluster":
                items = _paginate(rds, "describe_db_cluster_parameters", "Parameters", DBClusterParameterGroupName=name)
            else:
                items = _paginate(rds, "describe_db_parameters", "Parameters", DBParameterGroupName=name)
            parameter_cache[(kind, name)] = {p["ParameterName"]: p.get("ParameterValue") for p in items}
        return parameter_cache[(kind, name)]

    for cluster in _paginate(rds, "describe_db_clusters", "DBClusters"):
        if not _is_rds(cluster.get("Engine")):
            continue
        arn = cluster["DBClusterArn"]
        masters.append((cluster["DbClusterResourceId"], cluster.get("MasterUsername", "")))
        findings += check_credentials(cluster, arn, account_id)
        group = cluster.get("DBClusterParameterGroup")
        if group:
            findings += check_transport(cluster["Engine"], parameters("cluster", group), group, arn, account_id)

    for instance in _paginate(rds, "describe_db_instances", "DBInstances"):
        if not _is_rds(instance.get("Engine")):
            continue
        arn = instance["DBInstanceArn"]
        group_ids = [g["VpcSecurityGroupId"] for g in instance.get("VpcSecurityGroups", [])]
        groups = []
        if instance.get("PubliclyAccessible") and group_ids:
            groups = ec2.describe_security_groups(GroupIds=group_ids)["SecurityGroups"]
        findings += check_public_access(instance, groups, account_id)
        if instance.get("DBClusterIdentifier"):
            continue
        masters.append((instance["DbiResourceId"], instance.get("MasterUsername", "")))
        findings += check_credentials(instance, arn, account_id)
        for group in instance.get("DBParameterGroups", [])[:1]:
            name = group["DBParameterGroupName"]
            findings += check_transport(instance["Engine"], parameters("instance", name), name, arn, account_id)
    return findings, masters


def audit_account(account_id, client, regions):
    """Run every check in one account. client(service, region) returns a
    boto3 client with that account's credentials."""
    findings, masters = [], []
    for region in regions:
        region_findings, region_masters = audit_region(account_id, client("rds", region), client("ec2", region))
        findings += region_findings
        masters += region_masters
    findings += check_iam(_authorization_details(client("iam", None)), masters, account_id)
    return findings


def _organization_accounts():
    """Active organization account IDs, or None without Organizations access."""
    try:
        return [
            a["Id"]
            for page in organizations.get_paginator("list_accounts").paginate()
            for a in page["Accounts"]
            if (a.get("State") or a.get("Status") or "ACTIVE") == "ACTIVE"
        ]
    except ClientError:
        logger.exception("Could not list organization accounts; scanning this account only")
        return None


def _client_factory(credentials=None):
    session = boto3.Session(
        aws_access_key_id=credentials and credentials["AccessKeyId"],
        aws_secret_access_key=credentials and credentials["SecretAccessKey"],
        aws_session_token=credentials and credentials["SessionToken"],
    )
    return lambda service, region: session.client(service, region_name=region)


def _member_client(partition, account_id):
    role_arn = f"arn:{partition}:iam::{account_id}:role/{MEMBER_ROLE_NAME}"
    credentials = sts.assume_role(RoleArn=role_arn, RoleSessionName="rds-access-auditor")["Credentials"]
    return _client_factory(credentials)


def _report(findings, errors, org_listed):
    lines = [f"RDS access audit: {len(findings)} finding(s)."]
    if MEMBER_ROLE_NAME and not org_listed:
        lines.append("Organization accounts could not be listed, so only this account was scanned.")
    for severity in SEVERITIES:
        matching = [f for f in findings if f["severity"] == severity]
        if not matching:
            continue
        lines.append(f"\n=== {severity} ({len(matching)}) ===")
        for f in matching:
            lines.append(f"[{f['check']}] {f['account']} {f['resource']}\n  {f['detail']}")
    if errors:
        lines.append(f"\n=== Accounts not scanned ({len(errors)}) ===")
        lines.extend(f"{account}: {error}" for account, error in errors)
    return "\n".join(lines)


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")


def lambda_handler(event, context):
    identity = sts.get_caller_identity()
    own_account = identity["Account"]
    partition = identity["Arn"].split(":")[1]
    regions = REGIONS or [os.environ.get("AWS_REGION") or os.environ["AWS_DEFAULT_REGION"]]

    targets = [own_account]
    org_accounts = _organization_accounts() if MEMBER_ROLE_NAME else None
    if org_accounts:
        targets += sorted(a for a in org_accounts if a != own_account)

    findings, errors = [], []
    for account_id in targets:
        try:
            client = _client_factory() if account_id == own_account else _member_client(partition, account_id)
            findings += audit_account(account_id, client, regions)
        except ClientError as exc:
            # One unreachable account shouldn't hide the others' findings,
            # but it must show up in the report, not look clean.
            logger.exception("Could not audit account %s", account_id)
            errors.append((account_id, exc.response["Error"]["Code"]))

    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["account"], f["resource"]))
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    logger.info(json.dumps({"counts": counts, "accounts": len(targets), "errors": len(errors)}))

    if findings or errors:
        subject = f"RDS access audit: {counts['CRITICAL']} critical, {counts['HIGH']} high"
        _notify(subject, _report(findings, errors, org_accounts is not None))

    return {"counts": counts, "accounts_scanned": len(targets) - len(errors), "errors": errors, "findings": findings}
