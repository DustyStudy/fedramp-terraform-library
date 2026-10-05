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

import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# IAM Identity Center has no separate FIPS endpoints in the commercial
# partition; in GovCloud the standard endpoint is the FIPS one.
_NO_FIPS_VARIANT = Config(use_fips_endpoint=False)

organizations = boto3.client("organizations")
sso_admin = boto3.client("sso-admin", config=_NO_FIPS_VARIANT)
identitystore = boto3.client("identitystore", config=_NO_FIPS_VARIANT)
cloudtrail = boto3.client("cloudtrail")
iam = boto3.client("iam")
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
