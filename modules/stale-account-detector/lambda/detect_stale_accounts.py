"""
Reports inactive access across an AWS Organization: IAM users and their
credentials, roles (pipeline roles separately), IAM Identity Center users
and their account access, and whole AWS accounts. Report-only: every call
this function makes is read-only, and nothing is disabled or deleted.

"Stale" means the later of an identity's creation time and its last-used
time is older than INACTIVITY_DAYS. A new identity that has never been
used is not reported until it is that old.

Data sources:
  - IAM credential report and RoleLastUsed, read in each account through
    MEMBER_ROLE_NAME (the management account is read directly).
  - CloudTrail event history (90 days) in the management account for
    Identity Center sign-ins (UserAuthentication) and account access
    (GetRoleCredentials).

Env vars:
  SNS_TOPIC_ARN        - where the report goes
  INACTIVITY_DAYS      - window in days, 1-90 (default 90)
  MEMBER_ROLE_NAME     - read-only role to assume in member accounts;
                         empty reads only this account's IAM
  IGNORED_ROLE_NAMES   - comma-separated roles whose use is not account
                         activity (scanners that run everywhere)
  EXCLUDED_ACCOUNT_IDS - comma-separated account IDs to skip
  EXEMPT_TAG_KEY       - tag key that exempts an account, user or role
  EXEMPT_TAG_VALUE     - optional value the tag must have
  REPORT_POLL_SECONDS  - wait between credential report polls (default 2)
"""

import csv
import io
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# IAM Identity Center has no separate FIPS endpoints in the commercial
# partition; in GovCloud the standard endpoint is the FIPS one.
_NO_FIPS_VARIANT = Config(use_fips_endpoint=False)

organizations = boto3.client("organizations")
sso_admin = boto3.client("sso-admin", config=_NO_FIPS_VARIANT)
identitystore = boto3.client("identitystore", config=_NO_FIPS_VARIANT)
cloudtrail = boto3.client("cloudtrail")
# One GetRole per role adds up; the default four attempts turn throttling
# into an unread account.
_IAM_RETRIES = Config(retries={"mode": "standard", "max_attempts": 10})
iam = boto3.client("iam", config=_IAM_RETRIES)
sts = boto3.client("sts")
sns = boto3.client("sns")


def _csv_env(name):
    return {v.strip() for v in os.environ.get(name, "").split(",") if v.strip()}


SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
INACTIVITY_DAYS = int(os.environ.get("INACTIVITY_DAYS", "90"))
MEMBER_ROLE_NAME = os.environ.get("MEMBER_ROLE_NAME", "").strip()
# The member role is assumed on every run, so it never counts as activity.
IGNORED_ROLE_NAMES = _csv_env("IGNORED_ROLE_NAMES") | ({MEMBER_ROLE_NAME} if MEMBER_ROLE_NAME else set())
EXCLUDED_ACCOUNT_IDS = _csv_env("EXCLUDED_ACCOUNT_IDS")
EXEMPT_TAG_KEY = os.environ.get("EXEMPT_TAG_KEY") or None
EXEMPT_TAG_VALUE = os.environ.get("EXEMPT_TAG_VALUE") or None
REPORT_POLL_SECONDS = float(os.environ.get("REPORT_POLL_SECONDS", "2"))

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
# SNS rejects messages over 256 KB.
MAX_MESSAGE_BYTES = 250_000
_NO_TIME = {"", "N/A", "no_information", "not_supported"}


def _finding(severity, check, account_id, resource, detail):
    return {"severity": severity, "check": check, "account": account_id, "resource": resource, "detail": detail}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_time(value):
    """A timezone-aware datetime, or None for a missing or placeholder value."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None or value in _NO_TIME:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_stale(created, last_used, now):
    latest = max((t for t in (created, last_used) if t), default=None)
    return latest is None or now - latest > timedelta(days=INACTIVITY_DAYS)


def _age(last_used, now):
    return "never used" if last_used is None else f"last used {(now - last_used).days} days ago"


def _exempt(tags):
    if not EXEMPT_TAG_KEY:
        return False
    return any(
        tag["Key"] == EXEMPT_TAG_KEY and (EXEMPT_TAG_VALUE is None or tag["Value"] == EXEMPT_TAG_VALUE)
        for tag in tags or []
    )


# --- IAM users (one credential report row each) -------------------------------


def check_iam_user(row, account_id, now):
    if row["user"] == "<root_account>":
        return []
    findings = []
    created = parse_time(row.get("user_creation_time"))

    if row.get("password_enabled") == "true":
        changed = parse_time(row.get("password_last_changed")) or created
        used = parse_time(row.get("password_last_used"))
        if is_stale(changed, used, now):
            findings.append(_finding("MEDIUM", "iam-user-password", account_id, row["arn"], f"console password {_age(used, now)}"))

    for slot in ("1", "2"):
        if row.get(f"access_key_{slot}_active") != "true":
            continue
        rotated = parse_time(row.get(f"access_key_{slot}_last_rotated")) or created
        used = parse_time(row.get(f"access_key_{slot}_last_used_date"))
        if is_stale(rotated, used, now):
            resource = f"{row['arn']} access key {slot}"
            findings.append(_finding("HIGH", "iam-access-key", account_id, resource, f"active access key {_age(used, now)}"))
    return findings


# --- IAM roles (the Role dict from iam:GetRole) --------------------------------


def classify_role(role):
    if role.get("Path", "/").startswith("/aws-service-role/"):
        return "service-linked"
    if role["RoleName"].startswith("AWSReservedSSO_"):
        return "sso"
    for statement in _as_list((role.get("AssumeRolePolicyDocument") or {}).get("Statement")):
        principal = statement.get("Principal")
        federated = _as_list(principal.get("Federated")) if isinstance(principal, dict) else []
        if any("oidc-provider/" in value for value in federated):
            return "pipeline"
    return "other"


def role_last_used(role):
    return parse_time((role.get("RoleLastUsed") or {}).get("LastUsedDate"))


def check_role(role, account_id, now):
    kind = classify_role(role)
    # Identity Center roles are covered per user by sso-access.
    if kind in ("service-linked", "sso") or _exempt(role.get("Tags")):
        return []
    used = role_last_used(role)
    if not is_stale(parse_time(role.get("CreateDate")), used, now):
        return []
    if kind == "pipeline":
        return [_finding("MEDIUM", "pipeline-role", account_id, role["Arn"], f"OIDC-federated role {_age(used, now)}")]
    return [_finding("LOW", "iam-role", account_id, role["Arn"], f"role {_age(used, now)}")]


# --- AWS accounts ----------------------------------------------------------------

_USER_LAST_USED_FIELDS = ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date")


def account_last_activity(rows, roles):
    times = []
    for row in rows:
        if row["user"] != "<root_account>":
            times += [parse_time(row.get(field)) for field in _USER_LAST_USED_FIELDS]
    for role in roles:
        if classify_role(role) != "service-linked" and role["RoleName"] not in IGNORED_ROLE_NAMES:
            times.append(role_last_used(role))
    return max((t for t in times if t), default=None)


def check_account(account, rows, roles, now):
    used = account_last_activity(rows, roles)
    if not is_stale(parse_time(account.get("JoinedTimestamp")), used, now):
        return []
    resource = f"{account['Name']} ({account['Id']})"
    return [_finding("MEDIUM", "aws-account", account["Id"], resource, f"no user, access key or role in the account: {_age(used, now)}")]


# --- IAM Identity Center ---------------------------------------------------------


def check_sso_users(users, assigned_user_ids, last_sign_in, account_id, now):
    findings = []
    for user_id in sorted(assigned_user_ids):
        user = users.get(user_id)
        if not user or not user["enabled"]:
            continue
        used = last_sign_in.get(user_id)
        if is_stale(user["created"], used, now):
            detail = f"has account assignments and no sign-in in the last {INACTIVITY_DAYS} days"
            findings.append(_finding("MEDIUM", "sso-user", account_id, f"user {user['name']}", detail))
    return findings


def check_sso_access(assignments, last_access, users, now):
    findings = []
    for key in sorted(assignments):
        user_id, account_id, permission_set = key
        user = users.get(user_id)
        if not user or not user["enabled"]:
            continue
        # Identity Center does not record when an assignment was made, so a
        # new, unused assignment is reported.
        if is_stale(None, last_access.get(key), now):
            resource = f"user {user['name']} with permission set {permission_set}"
            detail = f"assigned to this account but not used in the last {INACTIVITY_DAYS} days"
            findings.append(_finding("LOW", "sso-access", account_id, resource, detail))
    return findings


# --- collectors: IAM -------------------------------------------------------------


def credential_report(iam_client):
    for _ in range(30):
        if iam_client.generate_credential_report()["State"] == "COMPLETE":
            content = iam_client.get_credential_report()["Content"]
            return list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
        time.sleep(REPORT_POLL_SECONDS)
    raise RuntimeError("credential report was not ready after 30 polls")


def list_roles(iam_client):
    # ListRoles leaves RoleLastUsed and Tags out; GetRole returns both.
    # Service-linked roles are never reported and never count as activity,
    # so their summary is enough.
    roles = []
    for page in iam_client.get_paginator("list_roles").paginate():
        for summary in page["Roles"]:
            if classify_role(summary) == "service-linked":
                roles.append(summary)
            else:
                roles.append(iam_client.get_role(RoleName=summary["RoleName"])["Role"])
    return roles


def exempt_user_names(iam_client, rows):
    if not EXEMPT_TAG_KEY:
        return set()
    names = set()
    for row in rows:
        if row["user"] != "<root_account>" and _exempt(iam_client.list_user_tags(UserName=row["user"])["Tags"]):
            names.add(row["user"])
    return names


# --- collectors: CloudTrail event history ----------------------------------------


class LookupTimeout(Exception):
    """The event history could not be read in the time the function has."""


def _lookup_events(event_name, start, deadline):
    # ponytail: LookupEvents is 50 events a page at 2 requests a second. An
    # organization with heavy Identity Center use can outgrow it; read an
    # organization trail with Athena here if that happens.
    paginator = cloudtrail.get_paginator("lookup_events")
    attributes = [{"AttributeKey": "EventName", "AttributeValue": event_name}]
    for page in paginator.paginate(LookupAttributes=attributes, StartTime=start):
        if time.monotonic() > deadline:
            raise LookupTimeout(f"ran out of time reading {event_name} events")
        for event in page["Events"]:
            yield parse_time(event["EventTime"]), json.loads(event["CloudTrailEvent"])


def _event_user(detail):
    return ((detail.get("userIdentity") or {}).get("onBehalfOf") or {}).get("userId")


def _keep_latest(latest, key, when):
    if key not in latest or when > latest[key]:
        latest[key] = when


def sso_activity(start, deadline):
    last_sign_in, last_access = {}, {}
    for when, detail in _lookup_events("UserAuthentication", start, deadline):
        user_id = _event_user(detail)
        if user_id and (detail.get("serviceEventDetails") or {}).get("UserAuthentication") == "Success":
            _keep_latest(last_sign_in, user_id, when)
    # The access portal logs Federate when a user opens an account console
    # and GetRoleCredentials when they take credentials for the CLI.
    for event_name in ("Federate", "GetRoleCredentials"):
        for when, detail in _lookup_events(event_name, start, deadline):
            details = detail.get("serviceEventDetails") or {}
            key = (_event_user(detail), details.get("account_id"), details.get("role_name"))
            if all(key) and not detail.get("errorCode"):
                _keep_latest(last_access, key, when)
    return last_sign_in, last_access


# --- collectors: IAM Identity Center ---------------------------------------------


def identity_center_assignments(instance):
    store, instance_arn = instance["IdentityStoreId"], instance["InstanceArn"]

    users = {}
    for page in identitystore.get_paginator("list_users").paginate(IdentityStoreId=store):
        for user in page["Users"]:
            users[user["UserId"]] = {
                "name": user["UserName"],
                "created": parse_time(user.get("CreatedAt")),
                "enabled": user.get("UserStatus", "ENABLED") != "DISABLED",
            }

    members = {}

    def group_members(group_id):
        if group_id not in members:
            paginator = identitystore.get_paginator("list_group_memberships")
            members[group_id] = [
                m["MemberId"]["UserId"]
                for page in paginator.paginate(IdentityStoreId=store, GroupId=group_id)
                for m in page["GroupMemberships"]
                if "UserId" in m["MemberId"]
            ]
        return members[group_id]

    assignments = set()
    for page in sso_admin.get_paginator("list_permission_sets").paginate(InstanceArn=instance_arn):
        for permission_set_arn in page["PermissionSets"]:
            common = {"InstanceArn": instance_arn, "PermissionSetArn": permission_set_arn}
            name = sso_admin.describe_permission_set(**common)["PermissionSet"]["Name"]
            for accounts in sso_admin.get_paginator("list_accounts_for_provisioned_permission_set").paginate(**common):
                for account_id in accounts["AccountIds"]:
                    for assigned in sso_admin.get_paginator("list_account_assignments").paginate(AccountId=account_id, **common):
                        for assignment in assigned["AccountAssignments"]:
                            principal = assignment["PrincipalId"]
                            user_ids = [principal] if assignment["PrincipalType"] == "USER" else group_members(principal)
                            assignments.update((user_id, account_id, name) for user_id in user_ids)
    return users, assignments


# --- handler ---------------------------------------------------------------------


def target_accounts():
    accounts = []
    for page in organizations.get_paginator("list_accounts").paginate():
        for account in page["Accounts"]:
            # Organizations is replacing Status with State. An account with
            # neither is read, never silently dropped.
            state = account.get("State") or account.get("Status")
            if (state and state != "ACTIVE") or account["Id"] in EXCLUDED_ACCOUNT_IDS:
                continue
            if EXEMPT_TAG_KEY and _exempt(organizations.list_tags_for_resource(ResourceId=account["Id"])["Tags"]):
                continue
            accounts.append(account)
    return accounts


def iam_client_for(account_id, own_account_id, partition):
    if account_id == own_account_id:
        return iam
    if not MEMBER_ROLE_NAME:
        return None
    role_arn = f"arn:{partition}:iam::{account_id}:role/{MEMBER_ROLE_NAME}"
    credentials = sts.assume_role(RoleArn=role_arn, RoleSessionName="stale-account-detector")["Credentials"]
    return boto3.client(
        "iam",
        config=_IAM_RETRIES,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def scan_account(account, iam_client, now):
    rows = credential_report(iam_client)
    roles = list_roles(iam_client)
    exempt = exempt_user_names(iam_client, rows)
    findings = []
    for row in rows:
        if row["user"] not in exempt:
            findings += check_iam_user(row, account["Id"], now)
    for role in roles:
        findings += check_role(role, account["Id"], now)
    return findings + check_account(account, rows, roles, now)


def scan_identity_center(own_account_id, now, deadline, account_ids):
    instances = sso_admin.list_instances()["Instances"]
    if not instances:
        return None
    users, assignments = identity_center_assignments(instances[0])
    last_sign_in, last_access = sso_activity(now - timedelta(days=INACTIVITY_DAYS), deadline)
    # A portal session can outlive a short window, so taking credentials or
    # opening a console counts as the user being active too.
    last_seen = dict(last_sign_in)
    for (user_id, _, _), when in last_access.items():
        _keep_latest(last_seen, user_id, when)
    assigned = {user_id for user_id, _, _ in assignments}
    # Excluded, exempt and closed accounts are skipped here as everywhere else.
    in_scope = {key for key in assignments if key[1] in account_ids}
    return check_sso_users(users, assigned, last_seen, own_account_id, now) + check_sso_access(
        in_scope, last_access, users, now
    )


def _publish(findings, errors, not_checked, counts):
    lines = [f"Stale access report: {len(findings)} finding(s) over {INACTIVITY_DAYS} days of inactivity."]
    for item in not_checked:
        lines.append(f"Not checked - {item}")
    for error in errors:
        lines.append(f"Could not read account {error['account']}: {error['error']}")
    for severity in SEVERITIES:
        matching = [f for f in findings if f["severity"] == severity]
        if matching:
            lines.append(f"\n=== {severity} ({len(matching)}) ===")
            lines += [f"[{f['check']}] {f['account']} {f['resource']}\n  {f['detail']}" for f in matching]
    subject = f"Stale access: {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low"
    # The schedule discards the return value, so the log keeps the totals.
    by_check = {check: sum(f["check"] == check for f in findings) for check in sorted({f["check"] for f in findings})}
    logger.info("Findings by check: %s; errors: %d; not checked: %s", json.dumps(by_check), len(errors), not_checked)

    kept, size = [], 0
    for line in lines:
        size += len(line.encode("utf-8")) + 1
        if size > MAX_MESSAGE_BYTES - 200:  # room for the closing line
            kept.append(f"\n... {len(lines) - len(kept)} more finding(s) not shown. Invoke the function for the full list.")
            break
        kept.append(line)
    if SNS_TOPIC_ARN:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message="\n".join(kept))


def lambda_handler(event, context):
    now = datetime.now(timezone.utc)
    # Leave two minutes to finish the report after the event lookups.
    remaining = context.get_remaining_time_in_millis() / 1000 if context else 900
    deadline = time.monotonic() + max(remaining - 120, 0)

    identity = sts.get_caller_identity()
    own_account_id, partition = identity["Account"], identity["Arn"].split(":")[1]
    findings, errors, not_checked = [], [], []
    scanned = unread = out_of_time = 0

    accounts = target_accounts()
    for account in accounts:
        if time.monotonic() >= deadline:
            out_of_time += 1
            continue
        try:
            client = iam_client_for(account["Id"], own_account_id, partition)
            if client is None:
                unread += 1
                continue
            findings += scan_account(account, client, now)
            scanned += 1
        except (ClientError, BotoCoreError, RuntimeError) as exc:
            logger.warning("Could not read account %s: %s", account["Id"], exc)
            errors.append({"account": account["Id"], "error": str(exc)})
    if unread:
        not_checked.append(f"IAM in {unread} member account(s): member_role_name is not set")
    if out_of_time:
        not_checked.append(f"IAM in {out_of_time} account(s): ran out of time")

    try:
        sso_findings = scan_identity_center(own_account_id, now, deadline, {a["Id"] for a in accounts})
        if sso_findings is None:
            not_checked.append("sso-user and sso-access: no IAM Identity Center instance in this region")
        else:
            findings += sso_findings
    except (ClientError, BotoCoreError, LookupTimeout) as exc:
        logger.warning("Identity Center checks did not run: %s", exc)
        not_checked.append(f"sso-user and sso-access: {exc}")

    counts = {severity: sum(f["severity"] == severity for f in findings) for severity in SEVERITIES}
    if findings or errors or not_checked:
        _publish(findings, errors, not_checked, counts)
    else:
        logger.info("No stale access found - no notification sent")
    return {"counts": counts, "accounts_scanned": scanned, "errors": errors, "not_checked": not_checked, "findings": findings}
