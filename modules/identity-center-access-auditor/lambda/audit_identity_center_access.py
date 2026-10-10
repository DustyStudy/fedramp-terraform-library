"""
Audits AWS IAM Identity Center (successor to AWS SSO) for common
access-governance risks, on a schedule, and publishes a summary to SNS.
Detective only - never modifies a permission set or assignment, since
automatically revoking access could break someone's job in the middle
of their day. A human should review and right-size deliberately.

Three checks, run across every Identity Center instance in the account
(normally exactly one - the Organization instance):

1. Over-privileged permission sets: any permission set with the
   AdministratorAccess AWS-managed policy attached, or an inline policy
   statement granting a full wildcard action ("*") or a service-wide
   wildcard (e.g. "iam:*") on a sensitive service combined with
   Resource "*". Reported together with how many accounts it's
   provisioned to and whether it's assigned directly to a user (see
   check 2) - a permission set like this assigned org-wide is a very
   different risk than one assigned to a single break-glass group in
   one account.
   Also flagged: an inline statement that allows a named privilege
   escalation action (iam:PutRolePolicy, iam:AttachRolePolicy,
   iam:DeleteRolePermissionsBoundary, iam:PassRole,
   sso:CreateAccountAssignment and similar) on a wildcard resource. A
   permission set doesn't need "iam:*" to become admin: a user who can
   attach a policy to a role, or remove its permissions boundary, can
   grant themselves anything the boundary was meant to stop. Action
   patterns such as "iam:Put*" or "iam:*Policy" are matched too.
2. Direct-to-user account assignments: any account assignment whose
   principal is a user rather than a group. Independent of privilege
   level - this is a scalability/governance finding, not a severity
   one. Assignments should flow through groups so access can be
   reasoned about and rotated as people change teams, not tracked
   person-by-person across every account.
3. Unused permission sets: created but currently provisioned to zero
   accounts. Not a security finding on its own, just hygiene - reported
   as an informational addendum alongside real findings, never as the
   sole reason to notify.

Only AWS-managed policy content is evaluated for check 1. Customer-managed
policies attached to a permission set are counted and named in the report,
but their content isn't fetched - the underlying IAM policy for a
customer-managed reference lives per-account, not centrally, so evaluating
it would mean assuming a role in every target account. Out of scope for a
single-account auditor; see the README for how to extend this.

Env vars:
  SNS_TOPIC_ARN                - where to send the audit summary
  SENSITIVE_WILDCARD_SERVICES  - comma-separated list of IAM service
                                 prefixes where "<service>:*" + Resource
                                 "*" is flagged in an inline policy
                                 (default: iam, ec2, s3, kms,
                                 organizations, sts)
  ESCALATION_ACTIONS           - comma-separated IAM actions flagged when
                                 an inline statement allows them on a
                                 resource containing "*" (default:
                                 DEFAULT_ESCALATION_ACTIONS below)
  FLAG_DIRECT_USER_ASSIGNMENTS - "true"/"false" - enable check 2
                                 (default "true")
  REPORT_UNUSED_PERMISSION_SETS - "true"/"false" - include check 3's
                                 informational addendum when there's
                                 already something to report (default
                                 "true")
"""

import fnmatch
import json
import logging
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# IAM Identity Center has no separate FIPS endpoints: with
# AWS_USE_FIPS_ENDPOINT set, the SDK builds sso-fips.<region> and
# identitystore-fips.<region>, which do not exist in the commercial
# partition. In GovCloud the standard endpoint is the FIPS one.
_NO_FIPS_VARIANT = Config(use_fips_endpoint=False)
sso_admin = boto3.client("sso-admin", config=_NO_FIPS_VARIANT)
identitystore = boto3.client("identitystore", config=_NO_FIPS_VARIANT)
organizations = boto3.client("organizations")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
SENSITIVE_WILDCARD_SERVICES = [
    s.strip()
    for s in os.environ.get("SENSITIVE_WILDCARD_SERVICES", "iam,ec2,s3,kms,organizations,sts").split(",")
    if s.strip()
]
# IAM and Identity Center actions that let a principal raise its own or
# someone else's privileges. Grouped by technique: edit a policy, swap a
# policy version, change who can assume a role, drop a permissions
# boundary, mint credentials for another user, hand a role to a service,
# or change what an Identity Center permission set grants.
DEFAULT_ESCALATION_ACTIONS = (
    "iam:PutRolePolicy,iam:AttachRolePolicy,iam:PutUserPolicy,iam:AttachUserPolicy,"
    "iam:PutGroupPolicy,iam:AttachGroupPolicy,iam:AddUserToGroup,"
    "iam:CreatePolicyVersion,iam:SetDefaultPolicyVersion,iam:UpdateAssumeRolePolicy,"
    "iam:DeleteRolePermissionsBoundary,iam:PutRolePermissionsBoundary,"
    "iam:DeleteUserPermissionsBoundary,iam:PutUserPermissionsBoundary,"
    "iam:CreateAccessKey,iam:CreateLoginProfile,iam:UpdateLoginProfile,iam:PassRole,"
    "sso:CreateAccountAssignment,sso:PutInlinePolicyToPermissionSet,"
    "sso:AttachManagedPolicyToPermissionSet,sso:AttachCustomerManagedPolicyReferenceToPermissionSet,"
    "sso:DeletePermissionsBoundaryFromPermissionSet"
)
ESCALATION_ACTIONS = [
    a.strip().lower() for a in os.environ.get("ESCALATION_ACTIONS", DEFAULT_ESCALATION_ACTIONS).split(",") if a.strip()
]
FLAG_DIRECT_USER_ASSIGNMENTS = os.environ.get("FLAG_DIRECT_USER_ASSIGNMENTS", "true").lower() == "true"
REPORT_UNUSED_PERMISSION_SETS = os.environ.get("REPORT_UNUSED_PERMISSION_SETS", "true").lower() == "true"
ADMIN_POLICY_ARN_SUFFIX = "/AdministratorAccess"
MAX_MESSAGE_BYTES = 250_000  # SNS rejects a message over 256 KB


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    body = message.encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        message = body[:MAX_MESSAGE_BYTES].decode("utf-8", "ignore") + "\n... report truncated to fit SNS. The rest is not shown."
    # A publish error propagates: a report nobody received must fail the run
    # (Lambda Errors metric / DLQ), not look delivered.
    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)


def _paginate(client, operation, result_key, **kwargs):
    """API errors propagate: a detective audit that swallows AccessDenied
    would report a false "no findings", so let the invocation fail visibly
    (Lambda Errors metric / DLQ) instead. Callers that are genuinely
    best-effort catch ClientError themselves."""
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page.get(result_key, [])


def _account_name_map():
    """Best-effort AccountId -> Name lookup for readable reports. Returns
    an empty dict (falling back to raw account IDs everywhere) if the
    caller lacks organizations:ListAccounts - this auditor still works
    without it, just with less friendly output."""
    names = {}
    try:
        for account in _paginate(organizations, "list_accounts", "Accounts"):
            names[account["Id"]] = account.get("Name", account["Id"])
    except ClientError:
        logger.exception("Failed to list Organizations accounts - falling back to raw account IDs")
    return names


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _escalation_actions_allowed(action_patterns):
    """The escalation actions that any of the statement's action patterns
    match. IAM action names are case-insensitive and allow "*" and "?"
    wildcards, which fnmatch handles the same way once both sides are
    lowercased."""
    return [
        action
        for action in ESCALATION_ACTIONS
        if any(fnmatch.fnmatchcase(action, pattern) for pattern in action_patterns)
    ]


def _statement_is_risky(statement):
    """A full wildcard action, a service-wide wildcard on a sensitive
    service combined with a wildcard resource, or a named privilege
    escalation action on a resource that contains a wildcard."""
    if statement.get("Effect") != "Allow":
        return None

    actions = [a.lower() for a in _as_list(statement.get("Action"))]
    resources = _as_list(statement.get("Resource"))
    has_wildcard_resource = "*" in resources

    if "*" in actions:
        return "full wildcard action ('*')"

    # Allow + NotAction grants every action *except* the listed ones, which
    # on Resource "*" is effectively near-admin access.
    if statement.get("NotAction") is not None and has_wildcard_resource:
        return "Allow with NotAction on Resource '*' (grants everything except the listed actions)"

    if has_wildcard_resource:
        for action in actions:
            if ":" not in action:
                continue
            service, _, rest = action.partition(":")
            if rest == "*" and service in SENSITIVE_WILDCARD_SERVICES:
                return f"service-wide wildcard action ({action}) with Resource '*'"

    # A wildcard anywhere in the resource ("*", "arn:aws:iam::111:role/*")
    # means the action reaches roles or users the author didn't name.
    if any("*" in str(resource) for resource in resources):
        escalation = _escalation_actions_allowed(actions)
        if escalation:
            return (
                f"privilege escalation action(s) on a wildcard resource: {', '.join(escalation)} "
                "(can grant itself more access or remove a permissions boundary)"
            )

    return None


def _inline_policy_findings(instance_arn, permission_set_arn):
    findings = []
    # An API error propagates, as in _paginate: a policy that couldn't be
    # read must not look like a policy with nothing risky in it.
    doc_str = sso_admin.get_inline_policy_for_permission_set(
        InstanceArn=instance_arn, PermissionSetArn=permission_set_arn
    ).get("InlinePolicy")

    if not doc_str:
        return findings

    try:
        doc = json.loads(doc_str)
    except (TypeError, ValueError):
        logger.exception("Inline policy for %s was not valid JSON", permission_set_arn)
        return ["inline policy could not be parsed; review it by hand"]

    # "Statement" may be a single object rather than a list - both are valid IAM.
    for statement in _as_list(doc.get("Statement")):
        if not isinstance(statement, dict):
            continue
        reason = _statement_is_risky(statement)
        if reason:
            findings.append(f"inline policy statement ({statement.get('Sid', 'no Sid')}): {reason}")

    return findings


def _managed_policy_findings(instance_arn, permission_set_arn):
    has_admin = False
    other_managed = []
    for policy in _paginate(
        sso_admin,
        "list_managed_policies_in_permission_set",
        "AttachedManagedPolicies",
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn,
    ):
        arn = policy.get("Arn", "")
        if arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
            has_admin = True
        else:
            other_managed.append(policy.get("Name", arn))
    return has_admin, other_managed


def _customer_managed_policy_count(instance_arn, permission_set_arn):
    count = 0
    for _ in _paginate(
        sso_admin,
        "list_customer_managed_policy_references_in_permission_set",
        "CustomerManagedPolicyReferences",
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn,
    ):
        count += 1
    return count


def _provisioned_accounts(instance_arn, permission_set_arn):
    return list(
        _paginate(
            sso_admin,
            "list_accounts_for_provisioned_permission_set",
            "AccountIds",
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )
    )


def _resolve_principal_name(identity_store_id, principal_id, principal_type):
    try:
        if principal_type == "USER":
            return identitystore.describe_user(IdentityStoreId=identity_store_id, UserId=principal_id).get(
                "UserName", principal_id
            )
        return identitystore.describe_group(IdentityStoreId=identity_store_id, GroupId=principal_id).get(
            "DisplayName", principal_id
        )
    except ClientError:
        # Principal may have been deleted from the identity source after
        # the assignment was made, or Identity Store hasn't synced yet.
        return f"{principal_id} (could not resolve name)"


def _account_assignments(instance_arn, account_id, permission_set_arn):
    return list(
        _paginate(
            sso_admin,
            "list_account_assignments",
            "AccountAssignments",
            InstanceArn=instance_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set_arn,
        )
    )


def _audit_instance(instance_arn, identity_store_id, account_names):
    over_privileged = []
    direct_user_assignments = []
    unused_permission_sets = []

    for ps_arn in _paginate(sso_admin, "list_permission_sets", "PermissionSets", InstanceArn=instance_arn):
        try:
            ps_name = sso_admin.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=ps_arn)[
                "PermissionSet"
            ]["Name"]
        except ClientError:
            logger.exception("Failed to describe permission set %s", ps_arn)
            ps_name = ps_arn

        provisioned_accounts = _provisioned_accounts(instance_arn, ps_arn)

        if not provisioned_accounts:
            unused_permission_sets.append(ps_name)
            continue  # nothing assigned, so no assignments to walk below

        has_admin, other_managed = _managed_policy_findings(instance_arn, ps_arn)
        inline_findings = _inline_policy_findings(instance_arn, ps_arn)
        customer_managed_count = _customer_managed_policy_count(instance_arn, ps_arn)

        has_direct_user = False
        for account_id in provisioned_accounts:
            for assignment in _account_assignments(instance_arn, account_id, ps_arn):
                principal_type = assignment.get("PrincipalType")
                principal_id = assignment.get("PrincipalId")
                if principal_type == "USER":
                    has_direct_user = True
                    if FLAG_DIRECT_USER_ASSIGNMENTS:
                        principal_name = _resolve_principal_name(identity_store_id, principal_id, principal_type)
                        direct_user_assignments.append(
                            {
                                "permission_set": ps_name,
                                "account": account_names.get(account_id, account_id),
                                "user": principal_name,
                            }
                        )

        if has_admin or inline_findings:
            reasons = []
            if has_admin:
                reasons.append("AdministratorAccess attached")
            reasons.extend(inline_findings)
            over_privileged.append(
                {
                    "permission_set": ps_name,
                    "account_count": len(provisioned_accounts),
                    "accounts": [account_names.get(a, a) for a in provisioned_accounts],
                    "has_direct_user_assignment": has_direct_user,
                    "other_managed_policies": other_managed,
                    "customer_managed_policy_count": customer_managed_count,
                    "reasons": reasons,
                }
            )

    return over_privileged, direct_user_assignments, unused_permission_sets


def lambda_handler(event, context):
    logger.info("Starting Identity Center access audit")

    account_names = _account_name_map()
    all_over_privileged = []
    all_direct_user_assignments = []
    all_unused = []

    for instance in _paginate(sso_admin, "list_instances", "Instances"):
        instance_arn = instance["InstanceArn"]
        identity_store_id = instance["IdentityStoreId"]
        logger.info("Auditing Identity Center instance %s", instance_arn)

        over_privileged, direct_user_assignments, unused = _audit_instance(
            instance_arn, identity_store_id, account_names
        )
        all_over_privileged.extend(over_privileged)
        all_direct_user_assignments.extend(direct_user_assignments)
        all_unused.extend(unused)

    has_findings = bool(all_over_privileged or all_direct_user_assignments)

    if has_findings:
        lines = []

        if all_over_privileged:
            lines.append(f"\n=== Over-privileged permission sets ({len(all_over_privileged)}) ===")
            for p in all_over_privileged:
                lines.append(f"\nPermission set: {p['permission_set']}")
                lines.append(f"  Provisioned to {p['account_count']} account(s): {', '.join(p['accounts'])}")
                if p["has_direct_user_assignment"]:
                    lines.append("  ** Also assigned directly to at least one user, not just groups **")
                for reason in p["reasons"]:
                    lines.append(f"  - {reason}")
                if p["other_managed_policies"]:
                    lines.append(f"  Other AWS-managed policies attached: {', '.join(p['other_managed_policies'])}")
                if p["customer_managed_policy_count"]:
                    lines.append(
                        f"  {p['customer_managed_policy_count']} customer-managed policy reference(s) attached "
                        "(not evaluated - see module README)"
                    )

        if all_direct_user_assignments:
            lines.append(f"\n=== Direct-to-user account assignments ({len(all_direct_user_assignments)}) ===")
            lines.append("Assignments should generally flow through groups, not individual users:")
            for a in all_direct_user_assignments:
                lines.append(f"  - {a['user']} -> {a['permission_set']} on {a['account']}")

        if REPORT_UNUSED_PERMISSION_SETS and all_unused:
            lines.append(f"\n=== Unused permission sets ({len(all_unused)}) - informational, not a finding ===")
            lines.append("Created but currently provisioned to zero accounts:")
            for name in all_unused:
                lines.append(f"  - {name}")

        _notify(
            subject=(
                f"Identity Center audit: {len(all_over_privileged)} over-privileged permission set(s), "
                f"{len(all_direct_user_assignments)} direct-to-user assignment(s)"
            ),
            message=(
                "Review and right-size deliberately - this audit does not modify any "
                "permission set or assignment.\n" + "\n".join(lines)
            ),
        )
    else:
        logger.info("No Identity Center access-governance findings")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "over_privileged_permission_set_count": len(all_over_privileged),
                "direct_user_assignment_count": len(all_direct_user_assignments),
                "unused_permission_set_count": len(all_unused),
            }
        ),
    }
