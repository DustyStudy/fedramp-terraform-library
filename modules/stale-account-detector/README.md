# stale-account-detector

Reports access that nobody is using, across every account in an AWS
Organization, so a person can disable it:

| Check | Reported when | Severity |
|---|---|---|
| `iam-access-key` | An active access key has not been used in the window | HIGH |
| `iam-user-password` | A console password has not been used in the window | MEDIUM |
| `pipeline-role` | A role trusted by an OIDC provider (GitHub Actions and similar) has not been assumed | MEDIUM |
| `iam-role` | Any other role has not been assumed | LOW |
| `sso-user` | An IAM Identity Center user with assignments has not signed in | MEDIUM |
| `sso-access` | A user's assignment to an account and permission set has not been used | LOW |
| `aws-account` | Nothing in the account has been used | MEDIUM |

It is report-only. Every permission it holds is read-only, and it never
disables or deletes anything. Supports NIST SP 800-53 AC-2, AC-2(3) and
IA-4 as review input and evidence.

## How it decides

An identity is stale when the later of its creation time and its last use
is older than `inactivity_days` (default 90). A new identity that has
never been used is not reported until it is that old. Service-linked roles
are never reported.

- **IAM users and keys** come from each account's credential report.
- **Roles** come from each role's last-used timestamp, which IAM keeps for
  400 days.
- **Identity Center** has no last-sign-in API, so sign-ins and account
  access come from CloudTrail event history in the management account
  (`UserAuthentication` for sign-ins; `Federate` and
  `GetRoleCredentials` for opening an account's console or taking CLI
  credentials). Event history
  goes back 90 days, which is why `inactivity_days` cannot be higher.
  Group assignments are expanded to their members. Disabled users are
  skipped.
- **Accounts** are stale when no user, key or role in them was used.
  Roles in `ignored_role_names`, the member role and service-linked roles
  do not count as activity, because scanners use them in every account.

Identity Center does not record when an assignment was made, so a new
assignment that has not been used yet is reported by `sso-access`.

## Deploy

Deploy in the organization management account, in the IAM Identity Center
home region.

```hcl
module "stale_account_detector" {
  source = "github.com/DustyStudy/fedramp-terraform-library//modules/stale-account-detector?ref=v2.1.0"

  notification_email = "security@example.com"
  member_role_name   = "StaleAccountRead"
  ignored_role_names = ["ProwlerScan"]
}
```

Then create the role named by `member_role_name` in every member account,
for example with a CloudFormation StackSet: attach the
`member_role_policy_json` output and trust the `lambda_role_arn` output.
Without `member_role_name` only the management account's IAM is read, and
the report says the member accounts were not checked.

## Exemptions

- `excluded_account_ids` skips whole accounts.
- `exempt_tag_key` (and optionally `exempt_tag_value`) skips an account
  that carries the tag in AWS Organizations, and any IAM user or role that
  carries it.

## What the report looks like

The Lambda publishes to its SNS topic only when there is a finding, an
account it could not read, or a check it could not run. A check that could
not run is listed as "Not checked"; it is never reported as zero findings.
The Lambda also returns
`{counts, accounts_scanned, errors, not_checked, findings}`.

## Limits

- CloudTrail event lookups return 50 events a page at two requests a
  second. With heavy Identity Center use, reading 90 days can take
  minutes; the Lambda has a 15-minute timeout and lists the Identity
  Center checks as not checked if it runs out. An organization that
  outgrows this should read its organization trail with Athena instead.
- Accounts are read one after another, with one `GetRole` call per
  role. If the 15 minutes run out, the accounts not reached are listed
  as not checked and the report is still sent. Very large
  organizations should run one detector per group of accounts, using
  `excluded_account_ids`.
- SNS messages are limited to 256 KB. A longer report is cut, says how
  many findings were left out, and the totals per check are in the
  Lambda's log. Invoke the function directly for the full list.
- Root user activity and unused permissions inside a role that is in use
  are out of scope.

## Upgrading from 1.x

Version 1 queried a CloudTrail Lake event data store, which AWS no longer
offers to new customers. Version 2 does not use it.

1. Turn off termination protection on the version 1 store:
   `aws cloudtrail update-event-data-store --event-data-store <arn> --no-termination-protection-enabled`
2. Replace `activity_lookback_days` with `inactivity_days` (at most 90)
   and remove `create_event_data_store`, `existing_event_data_store_arn`
   and `event_data_store_retention_days`.
3. Apply. Terraform deletes the store the module created. A store you
   passed in with `existing_event_data_store_arn` is left alone.
4. Create the member role and set `member_role_name`.

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-2, AC-2(3), IA-4, CM-8 | KSI-IAM-AAM |

Flags access to disable and accounts to close; it doesn't disable anything
itself. It is the review input for AC-2(3)'s "disable inactive accounts".

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| code_signing_config_arn | Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip. | `string` | `null` | no |
| excluded_account_ids | Account IDs to always skip (break-glass accounts, intentionally idle sandboxes, log-archive accounts, etc.). | `list(string)` | `[]` | no |
| exempt_tag_key | Optional AWS Organizations account tag key. Accounts carrying this tag are skipped entirely. Leave empty to check every account. | `string` | `""` | no |
| exempt_tag_value | Optional value exempt_tag_key must match. Leave empty to exempt on the tag key's presence alone (any value). | `string` | `""` | no |
| ignored_role_names | Roles whose use does not count as account activity, such as scanner roles that run in every account. The member role is always ignored. These roles are still reported if they themselves go unused. | `list(string)` | `[]` | no |
| inactivity_days | Days without use after which an identity or account is reported. 1 through 90: CloudTrail event history, which the Identity Center checks read, goes back 90 days. Use 35 for FedRAMP High. | `number` | `90` | no |
| member_role_name | Name of the read-only role the Lambda assumes in each member account. Create it in every account with the member_role_policy_json output and a trust policy for the lambda_role_arn output. Empty reads only this account's IAM, and the report says the member accounts were not checked. | `string` | `""` | no |
| name_prefix | Prefix used for naming all resources created by this module. | `string` | `"stale-account-detector"` | no |
| notification_email | Optional email address to subscribe to the SNS topic for the stale-account report. Leave empty to skip. | `string` | `""` | no |
| reserved_concurrent_executions | Concurrency reserved for the Lambda. Set -1 to reserve none: accounts at the 10-execution quota floor (new and sandbox accounts) reject any reservation. | `number` | `1` | no |
| schedule_expression | EventBridge schedule expression controlling how often the scan runs. | `string` | `"rate(7 days)"` | no |
| use_fips_endpoint | Make the Lambda's AWS SDK calls through FIPS 140 validated endpoints (sets AWS_USE_FIPS_ENDPOINT). Default true, matching the provider setting in this library's root configurations. | `bool` | `true` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| lambda_function_arn | ARN of the stale-account detector Lambda function. |
| lambda_role_arn | The Lambda's role. Trust it in the member-account role named by member_role_name. |
| member_role_policy_json | Read-only permissions the member-account role needs. Attach it to the role named by member_role_name in each account. |
| sns_topic_arn | ARN of the SNS topic used for the stale-account report. |
<!-- END_TF_DOCS -->

## Notes

- The Lambda honors `EXEMPT_TAG_VALUE` only when it's non-empty, so
  leaving `exempt_tag_value` unset exempts on the tag key alone.
- This module does not read an organization trail's S3 bucket. It reads
  CloudTrail event history, which every account has without setup.
