"""
Audits who can reach into an AWS account from outside it, on a schedule,
and publishes a summary to SNS. Detective only - never edits a trust
policy, function policy or resource share, since cutting off a pipeline
or a vendor integration by surprise is its own incident.

Four checks:

1. OIDC trust (IAM roles). A role trusting an OIDC provider with no
   subject condition, or a wildcard in the owner or repository part of a
   GitHub subject, can be assumed by other people's workflows. A missing
   audience condition is reported too.
2. Cross-account trust (IAM roles). A role any AWS principal can assume
   ("*" with no organization, account or ARN condition), or one trusting
   an account outside the organization without an sts:ExternalId
   condition.
3. Lambda function policies. Invocation granted to everyone, a public
   function URL with no auth, a service principal with no SourceArn or
   SourceAccount (confused deputy), or an account outside the
   organization.
4. RAM resource shares owned by the account that allow principals outside
   the organization, or are shared with one.

"Outside the organization" needs organizations:ListAccounts, so run this
from the management account or a delegated administrator. Without it the
cross-account parts of checks 2-4 are skipped and the report says so.

Set MEMBER_ROLE_NAME to scan every active account in the organization by
assuming that role in each; leave it empty to scan only this account.

Env vars:
  SNS_TOPIC_ARN        - where to send the audit summary
  MEMBER_ROLE_NAME     - role to assume in member accounts ("" = this
                         account only)
  REGIONS              - comma-separated regions for Lambda and RAM
                         (default: the Lambda's own region). IAM is global.
  TRUSTED_ACCOUNT_IDS  - comma-separated accounts outside the organization
                         to treat as trusted (for example a vendor you've
                         reviewed)
"""

import json
import logging
import os
import re

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
TRUSTED_ACCOUNT_IDS = {a.strip() for a in os.environ.get("TRUSTED_ACCOUNT_IDS", "").split(",") if a.strip()}

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"
ACCOUNT_ID = re.compile(r"^\d{12}$")

# Any of these on a statement pins "*" or a service principal to known
# callers, so it isn't reported as open.
PRINCIPAL_SCOPING_KEYS = {
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceorgid",
    "aws:sourceorgpaths",
}
SERVICE_SCOPING_KEYS = {"aws:sourcearn", "aws:sourceaccount", "aws:sourceorgid", "lambda:eventsourcetoken"}


class Context:
    """What counts as "inside": the organization's accounts plus any
    trusted extras. org_accounts is None when the organization couldn't be
    listed, which turns the outside-the-org checks off."""

    def __init__(self, org_accounts, trusted=()):
        self.org_accounts = set(org_accounts) if org_accounts is not None else None
        self.trusted = set(trusted)

    def is_external(self, account_id):
        if self.org_accounts is None:
            return False
        return account_id not in self.org_accounts and account_id not in self.trusted


def _finding(severity, check, account_id, resource, detail):
    return {"severity": severity, "check": check, "account": account_id, "resource": resource, "detail": detail}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statements(document):
    if isinstance(document, str):
        document = json.loads(document)
    return [s for s in _as_list((document or {}).get("Statement")) if s.get("Effect") == "Allow"]


def _principals(statement):
    """(kind, value) pairs. A bare "*" principal counts as AWS "*"."""
    principal = statement.get("Principal")
    if principal == "*":
        return [("AWS", "*")]
    return [(kind, value) for kind, values in (principal or {}).items() for value in _as_list(values)]


def _conditions(statement):
    """{lowercased key: [(operator, [values])]}. Condition keys are case
    insensitive; values are not."""
    found = {}
    for operator, keyed in (statement.get("Condition") or {}).items():
        for key, values in keyed.items():
            found.setdefault(key.lower(), []).append((operator, [str(v) for v in _as_list(values)]))
    return found


def _account_of(principal):
    if ACCOUNT_ID.match(principal):
        return principal
    parts = principal.split(":")
    return parts[4] if len(parts) > 4 and ACCOUNT_ID.match(parts[4]) else None


# --- check 1 and 2: IAM role trust ------------------------------------------


def _wild(text):
    return "*" in text or "?" in text


def _github_sub_problem(pattern):
    """Severity and reason for one GitHub sub pattern used with a *Like
    operator, or None if it has no wildcard.

    Handles both subject formats: repo:OWNER/REPO:... and the one with
    immutable IDs, repo:OWNER@OWNER_ID/REPO@REPO_ID:... A wildcard in an ID
    slot still pins the name, so it isn't "any owner"."""
    if not _wild(pattern):
        return None
    parts = pattern.split(":", 2)
    if parts[0] != "repo" or len(parts) < 2:
        if _wild(parts[0]):
            return "CRITICAL", f"sub '{pattern}' matches every GitHub repository"
        return "MEDIUM", f"sub '{pattern}' uses a custom claim format with a wildcard; review it by hand"

    owner, _, repo = parts[1].partition("/")
    owner_name, _, owner_id = owner.partition("@")
    repo_name, _, repo_id = repo.partition("@")
    if _wild(owner_name):
        return "CRITICAL", f"sub '{pattern}' matches repositories of any GitHub owner"
    if _wild(repo_name):
        return "HIGH", f"sub '{pattern}' matches every repository of {owner_name}"

    ids_note = ""
    if _wild(owner_id) or _wild(repo_id):
        ids_note = "; the owner and repository IDs aren't pinned, so a reused name would match"
    if len(parts) < 3 or _wild(parts[2]):
        detail = f"sub '{pattern}' matches any branch, environment or pull request of {owner_name}/{repo_name}"
        return "MEDIUM", detail + ids_note
    if ids_note:
        return "LOW", f"sub '{pattern}'{ids_note}"
    return None


def _check_oidc(statement, federated, account_id, role_arn):
    # Lowercased to match _conditions: EKS provider IDs are upper case.
    host = federated.split("oidc-provider/", 1)[-1].lower()
    conditions = _conditions(statement)
    findings = []

    if f"{host}:aud" not in conditions:
        findings.append(_finding("HIGH", "oidc-trust", account_id, role_arn, f"trusts {host} with no audience (aud) condition"))

    subs = conditions.get(f"{host}:sub")
    if not subs:
        other_claims = sorted(k for k in conditions if k.startswith(f"{host}:") and not k.endswith(":aud"))
        if other_claims:
            detail = f"trusts {host} with no subject (sub) condition; limited only by {', '.join(other_claims)}"
            findings.append(_finding("HIGH", "oidc-trust", account_id, role_arn, detail))
        else:
            severity = "CRITICAL" if host == GITHUB_OIDC_HOST else "HIGH"
            detail = f"trusts {host} with no subject (sub) condition: any identity the provider issues can assume it"
            findings.append(_finding(severity, "oidc-trust", account_id, role_arn, detail))
        return findings

    if host != GITHUB_OIDC_HOST:
        return findings
    for operator, values in subs:
        if "Like" not in operator:
            continue
        for value in values:
            problem = _github_sub_problem(value)
            if problem:
                findings.append(_finding(problem[0], "oidc-trust", account_id, role_arn, problem[1]))
    return findings


def check_role_trust(role, account_id, ctx):
    """Findings for one IAM role (as returned by iam:ListRoles)."""
    if role.get("Path", "/").startswith("/aws-service-role/"):
        return []
    role_arn = role["Arn"]
    findings = []
    for statement in _statements(role.get("AssumeRolePolicyDocument")):
        conditions = _conditions(statement)
        for kind, value in _principals(statement):
            if kind == "Federated" and "saml-provider/" not in value:
                findings += _check_oidc(statement, value, account_id, role_arn)
            elif kind == "AWS" and value == "*":
                if not PRINCIPAL_SCOPING_KEYS & conditions.keys():
                    detail = "any AWS principal in any account can assume it (Principal '*' with no org, account or ARN condition)"
                    findings.append(_finding("CRITICAL", "cross-account-trust", account_id, role_arn, detail))
            elif kind == "AWS":
                other = _account_of(value)
                if other and other != account_id and ctx.is_external(other) and "sts:externalid" not in conditions:
                    detail = f"trusts {value}, outside the organization, with no sts:ExternalId condition"
                    findings.append(_finding("HIGH", "cross-account-trust", account_id, role_arn, detail))
    return findings


# --- check 3: Lambda function policies --------------------------------------


def check_function_policy(function_arn, policy, account_id, ctx):
    findings = []
    for statement in _statements(policy):
        conditions = _conditions(statement)
        for kind, value in _principals(statement):
            if kind == "AWS" and value == "*":
                url_auth = [v for _, values in conditions.get("lambda:functionurlauthtype", []) for v in values]
                if "NONE" in url_auth:
                    detail = "has a public function URL (AuthType NONE): anyone on the internet can invoke it"
                    findings.append(_finding("HIGH", "lambda-policy", account_id, function_arn, detail))
                elif not PRINCIPAL_SCOPING_KEYS & conditions.keys():
                    detail = "any AWS principal can invoke it (Principal '*' with no source or org condition)"
                    findings.append(_finding("CRITICAL", "lambda-policy", account_id, function_arn, detail))
            elif kind == "Service":
                if not SERVICE_SCOPING_KEYS & conditions.keys():
                    detail = (
                        f"{value} can invoke it with no aws:SourceArn or aws:SourceAccount condition, "
                        "so another account's resource can trigger it (confused deputy)"
                    )
                    findings.append(_finding("MEDIUM", "lambda-policy", account_id, function_arn, detail))
            elif kind == "AWS":
                other = _account_of(value)
                if other and other != account_id and ctx.is_external(other):
                    detail = f"{value}, outside the organization, can invoke it"
                    findings.append(_finding("HIGH", "lambda-policy", account_id, function_arn, detail))
    return findings


# --- check 4: RAM resource shares -------------------------------------------


def check_resource_share(share, principals, account_id, ctx):
    findings = []
    share_ref = f"{share['name']} ({share['resourceShareArn']})"
    if share.get("allowExternalPrincipals"):
        findings.append(
            _finding("MEDIUM", "ram-share", account_id, share_ref, "allows principals outside the organization")
        )
    for principal in principals:
        other = _account_of(principal)
        if other and ctx.is_external(other):
            findings.append(_finding("HIGH", "ram-share", account_id, share_ref, f"is shared with {principal}, outside the organization"))
    return findings


# --- collection -------------------------------------------------------------


def _paginate(client, operation, result_key, **kwargs):
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(result_key, [])


def audit_account(account_id, client, regions, ctx):
    """Run every check in one account. client(service, region) returns a
    boto3 client with that account's credentials."""
    findings = []
    for role in _paginate(client("iam", None), "list_roles", "Roles"):
        findings += check_role_trust(role, account_id, ctx)

    for region in regions:
        lambda_client = client("lambda", region)
        for function in _paginate(lambda_client, "list_functions", "Functions"):
            try:
                policy = lambda_client.get_policy(FunctionName=function["FunctionArn"])["Policy"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    continue
                raise
            findings += check_function_policy(function["FunctionArn"], policy, account_id, ctx)

        ram = client("ram", region)
        for share in _paginate(ram, "get_resource_shares", "resourceShares", resourceOwner="SELF"):
            if share.get("status") != "ACTIVE":
                continue
            associations = _paginate(
                ram,
                "get_resource_share_associations",
                "resourceShareAssociations",
                associationType="PRINCIPAL",
                resourceShareArns=[share["resourceShareArn"]],
            )
            principals = [a["associatedEntity"] for a in associations if a.get("status") == "ASSOCIATED"]
            findings += check_resource_share(share, principals, account_id, ctx)
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
        logger.exception("Could not list organization accounts; outside-the-org checks are off")
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
    credentials = sts.assume_role(RoleArn=role_arn, RoleSessionName="trust-policy-auditor")["Credentials"]
    return _client_factory(credentials)


def _report(findings, errors, ctx):
    lines = [f"Trust policy audit: {len(findings)} finding(s)."]
    if ctx.org_accounts is None:
        lines.append(
            "Organization accounts could not be listed, so trust in accounts outside the organization was not checked."
        )
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

    org_accounts = _organization_accounts()
    ctx = Context(org_accounts, TRUSTED_ACCOUNT_IDS)

    targets = [own_account]
    if MEMBER_ROLE_NAME and org_accounts:
        targets += sorted(a for a in org_accounts if a != own_account)

    findings, errors = [], []
    for account_id in targets:
        try:
            client = _client_factory() if account_id == own_account else _member_client(partition, account_id)
            findings += audit_account(account_id, client, regions, ctx)
        except ClientError as exc:
            # One unreachable account shouldn't hide the others' findings,
            # but it must show up in the report, not look clean.
            logger.exception("Could not audit account %s", account_id)
            errors.append((account_id, exc.response["Error"]["Code"]))

    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["account"], f["resource"]))
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    logger.info(json.dumps({"counts": counts, "accounts": len(targets), "errors": len(errors)}))

    if findings or errors:
        subject = f"Trust policy audit: {counts['CRITICAL']} critical, {counts['HIGH']} high"
        _notify(subject, _report(findings, errors, ctx))

    return {"counts": counts, "accounts_scanned": len(targets) - len(errors), "errors": errors, "findings": findings}
