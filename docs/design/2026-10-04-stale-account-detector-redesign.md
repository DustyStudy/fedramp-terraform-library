# stale-account-detector 2.0: design

Status: approved design, not yet implemented.

## Purpose

Report inactive access across an AWS Organization so a person can disable
it: IAM users and their credentials, roles (pipeline roles called out
separately), IAM Identity Center users and their account access, and whole
AWS accounts. This is the evidence and the review input for NIST SP 800-53
AC-2 (account management), AC-2(3) (disable inactive accounts) and IA-4
(identifier management).

The module is report-only. It never disables or deletes anything, and every
permission it holds is read-only.

## Why it is being redesigned

Version 1 answers one question, "which AWS accounts had no CloudTrail
activity in N days", with a CloudTrail Lake query. AWS no longer accepts
new CloudTrail Lake customers, so version 1 cannot be deployed in an
organization that has never used Lake (see
[LIVE-PROOF.md](../LIVE-PROOF.md)). Version 2 uses data every organization
already has, and widens the question from accounts to the identities
inside them.

## Decisions

| Decision | Choice | Reason |
|---|---|---|
| What is reported | Stale identities and stale AWS accounts, as separate report sections | An idle key inside a busy account is invisible to an account-level report |
| Action on a finding | Report only | Keeps the Lambda read-only in every account |
| Data source | IAM last-used data, plus CloudTrail event history for Identity Center | No new infrastructure, no per-query cost, available in every organization |
| Module name | Unchanged | "Account" in AC-2 covers user accounts; control mappings keep working |
| Version | 2.0.0, breaking | The CloudTrail Lake variables and output are removed |

Rejected: Athena over an organization trail bucket (needs Glue, a
workgroup, cross-account bucket access, and assumes a trail layout), and
the IAM Access Analyzer unused-access analyzer (charges per role and user,
and does not cover Identity Center sign-ins).

## Architecture

One Lambda, deployed in the organization management account in the IAM
Identity Center home region, run on a schedule by EventBridge. Packaging,
the KMS key, the DLQ, the encrypted log group and the SNS topic follow the
other auditor modules.

```
EventBridge schedule
        |
        v
   Lambda (management account, Identity Center home region)
        |-- organizations:ListAccounts, ListTagsForResource
        |-- sso-admin, identitystore: users, groups, assignments
        |-- cloudtrail:LookupEvents: Identity Center sign-in and access events
        |-- sts:AssumeRole -> member_role_name in each active account
        |        '-- iam: credential report, roles, role last used
        v
   SNS topic (report), JSON return value
```

The management account itself is read with the Lambda's own role.

## Reports

A finding has the same shape as the other auditors' findings:
`{severity, check, account, resource, detail}`.

| `check` | Resource | Stale when | Severity |
|---|---|---|---|
| `iam-user-password` | IAM user | Console password exists and was not used in the window | MEDIUM |
| `iam-access-key` | Access key | Key is active and was not used in the window | HIGH |
| `pipeline-role` | IAM role trusted by an OIDC provider | Not assumed in the window | MEDIUM |
| `iam-role` | Any other IAM role | Not assumed in the window | LOW |
| `sso-user` | Identity Center user with at least one assignment | No `UserAuthentication` event in the window | MEDIUM |
| `sso-access` | User, account and permission set | Assigned, directly or through a group, with no `GetRoleCredentials` event for that combination in the window | LOW |
| `aws-account` | AWS account | No password, key or role in the account was used in the window, after ignoring `ignored_role_names` | MEDIUM |

Rules that apply to every check:

- **Stale** means the later of the creation time and the last-used time is
  older than `inactivity_days`. A new identity that has never been used is
  not reported until it is that old.
- **Missing creation times.** Identity Center does not expose when an
  assignment was made, so a new assignment that has not been used yet is
  reported by `sso-access`; that is why the check is LOW. If a user record
  has no creation time, the user is treated as older than the window.
- **Service-linked roles** (path `/aws-service-role/`) are skipped.
- **Roles created by Identity Center** (`AWSReservedSSO_*`) are skipped in
  `iam-role`; `sso-access` covers them per user.
- **Exemptions.** `excluded_account_ids` and the account exempt tag skip a
  whole account. The same tag key on an IAM user or role skips that
  identity.
- **`ignored_role_names`** lists roles whose use does not count as account
  activity, for scanners that run in every account. They are still
  reported by `iam-role` if they go unused.

## Data sources

| Data | API | Notes |
|---|---|---|
| Accounts | `organizations:ListAccounts`, `ListTagsForResource` | ACTIVE accounts only |
| IAM users, passwords, keys | `iam:GenerateCredentialReport`, `GetCredentialReport` | One report per account. Poll until `COMPLETE`. |
| IAM user tags | `iam:ListUserTags` | Only when an exempt tag key is set |
| Roles | `iam:ListRoles`, `iam:GetRole` | `ListRoles` does not return `RoleLastUsed`; `GetRole` does. IAM keeps it for 400 days. |
| Identity Center users and groups | `identitystore:ListUsers`, `ListGroupMemberships` | |
| Assignments | `sso-admin:ListInstances`, `ListPermissionSets`, `ListAccountsForProvisionedPermissionSet`, `ListAccountAssignments` | Group assignments are expanded to their members |
| Sign-ins | `cloudtrail:LookupEvents`, `EventName = UserAuthentication` | `userIdentity.onBehalfOf.userId` is the identity store user ID |
| Account access | `cloudtrail:LookupEvents`, `EventName = GetRoleCredentials` | `serviceEventDetails` holds `account_id` and `role_name`; the role name maps to a permission set |

Both event names were confirmed in a real management account's event
history on 2026-10-04.

## Interface

Variables kept from version 1: `name_prefix`, `notification_email`,
`schedule_expression`, `excluded_account_ids`, `exempt_tag_key`,
`exempt_tag_value`, `code_signing_config_arn`, `use_fips_endpoint`,
`reserved_concurrent_executions`.

| Variable | Type | Default | Change |
|---|---|---|---|
| `inactivity_days` | number | `90` | Replaces `activity_lookback_days`. Validated to 1 through 90, the length of CloudTrail event history. Use 35 for FedRAMP High. |
| `member_role_name` | string | `""` | New. Read-only role to assume in each member account. Empty means only the management account's IAM is read, and the report says so. |
| `ignored_role_names` | list(string) | `[]` | New. Role names that do not count as account activity. |
| `create_event_data_store`, `existing_event_data_store_arn`, `event_data_store_retention_days` | | | Removed |

Outputs: `lambda_function_arn`, `lambda_role_arn`, `sns_topic_arn`, and
`member_role_policy_json` (new, the read-only policy for the member role).
`event_data_store_arn` is removed.

The Lambda returns
`{counts, accounts_scanned, errors, not_checked, findings}`, where `counts`
is keyed by severity as in the other auditors and `not_checked` lists any
report that could not run.

## Failure handling

- An account whose role cannot be assumed, or whose IAM calls fail, is
  added to `errors` and named in the notification. The run continues.
- An account with an error is never reported as a stale `aws-account`.
- If a CloudTrail lookup fails, `sso-user` and `sso-access` are added to
  `not_checked` and the notification says they were not checked. They do
  not report zero findings.
- With no Identity Center instance, the two SSO checks are skipped and
  listed in `not_checked`.
- The Identity Center clients ignore `AWS_USE_FIPS_ENDPOINT`, as in
  `identity-center-access-auditor`.
- A notification is sent only when there is a finding, an error or a
  skipped report.

## Known limit

`LookupEvents` returns 50 events per page and is rate-limited to two
requests per second. Ninety days of `GetRoleCredentials` events in an
organization with heavy Identity Center use can take minutes to read. The
Lambda has the 15-minute maximum timeout, and the code marks the lookup as
the place to swap in Athena over an organization trail if an adopter
outgrows it. If the lookup runs out of time, the SSO checks go to
`not_checked`.

## Permissions

Lambda role, all read-only: the Organizations, Identity Center, identity
store and CloudTrail actions listed above, the IAM read actions for the
management account, `sts:AssumeRole` on
`arn:<partition>:iam::*:role/<member_role_name>` only when
`member_role_name` is set, plus `sns:Publish` to its topic and the usual
log, KMS and DLQ access.

Member role policy: `iam:GenerateCredentialReport`,
`iam:GetCredentialReport`, `iam:ListRoles`, `iam:GetRole`,
`iam:ListUserTags`.

## Code layout

`lambda/detect_stale_accounts.py`, one file as in the other auditors:

- pure check functions, one per `check`, that take plain data (a parsed
  credential report row, a role dict, a user and its events) and return
  findings;
- collectors that call AWS and hand plain data to the checks;
- `lambda_handler`, which loops over accounts, gathers errors and
  publishes.

The checks hold all the judgment and need no AWS mocks to test.

## Testing

- **pytest** (`tests/python/`): for each check, cases for used, unused,
  never used and old, never used and new, and exempt. Handler cases for an
  unreadable account, a failed CloudTrail lookup, no Identity Center
  instance, group expansion, and `ignored_role_names` deciding whether an
  account is stale.
- **terraform test**: the Lambda role and the member policy contain no
  write actions; `sts:AssumeRole` is absent unless `member_role_name` is
  set and then names only that role; settings reach the Lambda
  environment; `inactivity_days` outside 1 through 90 is rejected.
- **Live**: `proof/management` deploys the module with a stale fixture
  IAM user and role, the Lambda is invoked, and the result is added to
  `docs/LIVE-PROOF.md`.

## Migration

Version 2 has no state in common with the event data store. Existing users
remove termination protection from the version 1 data store, upgrade, and
apply; Terraform destroys the store. The README and CHANGELOG carry these
steps.

## Out of scope

- Disabling or deleting anything.
- Publishing findings to Security Hub.
- Unused permissions inside a role that is in use.
- Root user activity.
