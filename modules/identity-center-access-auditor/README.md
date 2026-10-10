# identity-center-access-auditor

Audits AWS IAM Identity Center (successor to AWS SSO) on a schedule for
three common access-governance risks: over-privileged permission sets,
account assignments made directly to a user instead of a group, and
unused permission sets. **Detective only** — this never modifies a
permission set or assignment, since automatically revoking access could
break someone's job in the middle of their day. A human should review
and right-size deliberately.

## The risk this targets

Identity Center is where most organizations centralize *who can do what,
where* across an entire AWS Organization — which makes its own
misconfigurations high-leverage. A single permission set with
`AdministratorAccess` provisioned to every account is a much bigger
blast radius than the same mistake in one account's IAM. And because
Identity Center makes it just as easy to assign access to an individual
user as to a group, it's easy for "just this once" direct assignments to
accumulate quietly until nobody can say why a given person has access to
a given account without checking case by case.

## How it works

A scheduled EventBridge rule (default: daily) invokes the Lambda, which
walks every Identity Center instance in the account (normally exactly
one — the Organization instance) and runs three checks:

**1. Over-privileged permission sets** — for every permission set, the
Lambda checks:
   - Whether the `AdministratorAccess` AWS-managed policy is attached
   - Whether its inline policy contains a full wildcard action
     (`"Action": "*"`) or a service-wide wildcard (e.g. `iam:*`) on one
     of `sensitive_wildcard_services`, combined with `Resource: "*"`
   - Whether its inline policy allows a named **privilege escalation
     action** on a resource that contains `*`: policy edits
     (`iam:PutRolePolicy`, `iam:AttachRolePolicy` and the user and group
     versions), `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`,
     permissions boundary changes (`iam:DeleteRolePermissionsBoundary`),
     `iam:CreateAccessKey`, `iam:PassRole`, and Identity Center changes
     such as `sso:CreateAccountAssignment` or
     `sso:PutInlinePolicyToPermissionSet`. Patterns like `iam:Put*` count.
     A permission set doesn't need `iam:*` to become admin: whoever can
     attach a policy to a role or strip its boundary can grant themselves
     the rest. Self-service elevation workflows are a common way in.
     Override the list with `escalation_actions`.

   Any match is reported together with how many accounts the permission
   set is provisioned to and whether it's also assigned directly to a
   user (see check 2) — `AdministratorAccess` assigned org-wide is a very
   different risk than the same policy scoped to one break-glass group in
   one account.

**2. Direct-to-user account assignments** — independent of privilege
level, any account assignment whose principal is a user rather than a
group is flagged. Assignments should generally flow through groups so
access can be reasoned about and rotated as people change teams, not
tracked person-by-person across every account. Set
`flag_direct_user_assignments = false` to disable this check.

**3. Unused permission sets** — permission sets created but currently
provisioned to zero accounts. Not a security finding by itself, just
hygiene — reported as an informational addendum whenever the audit
already has real findings to report, never as the sole reason to notify.

Findings are combined into a single SNS summary. A clean scan (no
over-privileged permission sets and no direct-to-user assignments) sends
nothing, even if unused permission sets exist. An inline policy that
can't be read fails the invocation instead of counting as clean, as does
a failed publish; a report over the SNS size limit is cut and says so.

## Using Terraform

```hcl
module "identity_center_access_auditor" {
  source = "../../modules/identity-center-access-auditor"

  notification_email = "you@example.com"
}
```

Works the same in GovCloud.

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-2, AC-6, AC-6(7) | KSI-IAM-ELP, KSI-IAM-AAM |

Supports the periodic privilege review in AC-6(7) with a daily report.
Detective only: a human still does the review and the right-sizing.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| code_signing_config_arn | Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip. | `string` | `null` | no |
| escalation_actions | IAM and Identity Center actions flagged when a permission set's inline policy allows them on a resource that contains "*". Action patterns in the policy (such as "iam:Put*") are matched against this list. Leave null for the Lambda's built-in list: policy edits, policy versions, trust policy edits, permissions boundary changes, access keys and login profiles, iam:PassRole, and permission set changes. | `list(string)` | `null` | no |
| flag_direct_user_assignments | Flag account assignments made directly to a user rather than a group. Assignments should generally flow through groups so access can be reasoned about and rotated as people change teams. | `bool` | `true` | no |
| name_prefix | Prefix used for naming all resources created by this module. | `string` | `"identity-center-access-auditor"` | no |
| notification_email | Optional email address to subscribe to the SNS topic. Leave empty to skip. | `string` | `""` | no |
| report_unused_permission_sets | Include permission sets provisioned to zero accounts as an informational addendum whenever the audit already has other findings to report. This never triggers a notification by itself. | `bool` | `true` | no |
| reserved_concurrent_executions | Concurrency reserved for the Lambda. Set -1 to reserve none: accounts at the 10-execution quota floor (new and sandbox accounts) reject any reservation. | `number` | `2` | no |
| schedule_expression | EventBridge schedule expression controlling how often the audit runs. | `string` | `"rate(1 day)"` | no |
| sensitive_wildcard_services | IAM service prefixes where "<service>:*" combined with Resource "*" in a permission set's inline policy is flagged as over-broad. | `list(string)` | ```[ "iam", "ec2", "s3", "kms", "organizations", "sts" ]``` | no |
| use_fips_endpoint | Make the Lambda's AWS SDK calls through FIPS 140 validated endpoints (sets AWS_USE_FIPS_ENDPOINT). Default true, matching the provider setting in this library's root configurations. | `bool` | `true` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| lambda_function_arn | ARN of the auditor Lambda function. |
| sns_topic_arn | ARN of the SNS topic used for audit notifications. |
<!-- END_TF_DOCS -->

## Before you deploy

- **Deploy from the account where Identity Center is enabled** — the
  Organization's management account, or a delegated administrator
  account if you've registered one (Identity Center → Settings →
  Delegated administrator). Identity Center is Organization-wide, not
  per-account, so this only needs to run once.
- **Deploy in Identity Center's "home Region"** — check Identity Center
  → Settings → Details in the console for which Region your instance
  actually lives in, and point your AWS provider's `region` at it. The
  `sso-admin` API calls in this Lambda only see instances in the Region
  the Lambda itself runs in.

## Notes

- **IAM Action prefix vs. SDK client name**: the boto3/SDK client for this
  API is called `sso-admin`, but its IAM Action prefix is `sso:` (e.g.
  `sso:ListPermissionSets`) — the two don't match, which is easy to get
  wrong when hand-writing the Lambda's execution-role policy.
- Only **AWS-managed** policy content is evaluated for check 1.
  Customer-managed policies attached to a permission set are counted and
  named in the report, but their content isn't fetched — the underlying
  IAM policy for a customer-managed reference lives per-account, not
  centrally, so evaluating it would mean assuming a role in every target
  account. Out of scope for a single-account auditor; if your org relies
  heavily on customer-managed policies in permission sets, extend the
  Lambda to assume a read-only role into each target account and fetch
  the policy document there.
- Friendly account names in the report depend on `organizations:ListAccounts`,
  which is included in the module's IAM policy. If your delegated
  administrator account doesn't have Organizations read access for some
  reason, the report falls back to raw account IDs — everything else
  still works.
- This is purely additive to [`org-scp-boundary`](../org-scp-boundary/): SCPs
  constrain what an already-granted permission set can actually do
  account-wide; this audits how permission sets and assignments
  themselves are structured, which SCPs can't see into.
- False positives are expected and fine here — a break-glass permission
  set with `AdministratorAccess` scoped to a single group in a single
  account will still get flagged. The point is visibility into what
  exists, not a hard gate.
