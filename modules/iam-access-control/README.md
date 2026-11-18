# iam-access-control

Account-level IAM access control baseline: IAM Access Analyzer (external
and unused access), a permission boundary for human/developer roles,
enforced-MFA policy for IAM users, and root account usage alerting.

## Usage

```hcl
module "iam_access_control" {
  source = "../../moderate/iam-access-control"
}
```

## Control mapping

| Resource | Rev5 Controls | 20x KSI |
|---|---|---|
| Access Analyzer (external access) | AC-3, AC-6 | KSI-IAM-ELP |
| Access Analyzer (unused access) | AC-2(3) | KSI-IAM-JIT |
| Developer permission boundary | AC-6, AC-6(1) | KSI-IAM-ELP |
| Require-MFA IAM group policy | IA-2(1), AC-7 | KSI-IAM-APM |
| Root usage EventBridge rule + SNS | AC-6(5), AU-6 | KSI-IAM-SUS, KSI-MLA-RVL |

## Notes

- The require-MFA group governs IAM *users* only — SSO/Identity Center
  users authenticate through your IdP, so their MFA enforcement lives
  there, not in this module.
- The require-MFA policy only denies; it grants nothing. Users also need a
  policy that allows managing their own MFA device and password (AWS's
  "Allows MFA-authenticated IAM users to manage their own credentials"
  example is the matching set of Allow statements).
- The MFA deny exempts exactly what that AWS example exempts. A user created
  with "must reset password at next sign-in", or whose password has expired,
  therefore cannot sign in until an administrator resets it. AWS's advice is
  to create users without a forced reset. If you need the reset, set
  `allow_password_change_without_mfa = true` and accept that a password can
  then be changed without MFA.
- The boundary allows `lambda:*` on this account's functions. A role under
  it whose identity policy also allows updating a function can run code as
  that function's execution role, so scope the identity policy to the
  team's own functions.
- The permission boundary is a ceiling, not a grant — attach it via
  `permissions_boundary` when creating roles/users; it doesn't do anything
  by itself until referenced.
- `iam:PassRole` is the only IAM action under the boundary: roles under
  `developer_role_path` (default `/developer/`), passed to Lambda only. The
  boundary does not allow creating roles, so an administrator or pipeline
  creates the execution roles under that path. IAM cannot check the passed
  role's own boundary, so every role under the path is one a developer's
  function can run as.
- KMS use is limited to `kms:Decrypt` and `kms:GenerateDataKey*` through
  DynamoDB, Lambda, S3, SNS and SQS, on this account's keys; the key policy
  still has to grant it. CloudWatch Logs is limited to writing and reading
  `/aws/lambda/*` log groups.
- The boundary denies the actions that expose a resource to another account
  or the public: bucket policies, bucket ACLs and public access blocks,
  Lambda and layer permissions, DynamoDB resource policies, and SQS/SNS
  `AddPermission`. SQS and SNS set a policy through `SetQueueAttributes` /
  `SetTopicAttributes`, which are denied whole, so a principal under the
  boundary cannot change any attribute of an existing queue or topic (it can
  still set them at creation). Object ACLs are not denied; keep S3 Block
  Public Access on.
- The `DenyPrivilegeEscalation` and `DenyBoundaryRemoval` statements deny
  IAM actions the boundary does not allow in the first place. They are a
  second lock that starts to matter only if role or user management is
  added to the boundary.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| allow_password_change_without_mfa | Exempt iam:ChangePassword and iam:GetAccountPasswordPolicy from the require-MFA deny, so a user created with a forced password reset (or whose password expired) can set a password at sign-in before registering MFA. Off by default because AWS advises against it; while off, such a user cannot sign in, so create users without a forced reset. | `bool` | `false` | no |
| analyzer_type | Use ORGANIZATION if deploying from the delegated Access Analyzer administrator account to cover all member accounts; ACCOUNT for a single-account deployment. | `string` | `"ACCOUNT"` | no |
| developer_role_path | IAM path of the roles a principal under the developer boundary may pass to Lambda. Every role under this path is one a developer's function can run as, so keep the path for roles meant for that. | `string` | `"/developer/"` | no |
| root_usage_alert_topic_name | n/a | `string` | `"root-account-usage-alerts"` | no |
| unused_access_age | Days of inactivity before Access Analyzer flags a permission as unused (supports AC-2(3), periodic account review). | `number` | `90` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| external_access_analyzer_arn | ARN of the external-access analyzer |
| permission_boundary_arn | ARN to reference in permissions_boundary when creating human/developer IAM roles or users |
| require_mfa_group_name | IAM group name — add users here to enforce MFA |
| root_usage_alert_topic_arn | Subscribe your security team's email/Slack integration here |
| unused_access_analyzer_arn | ARN of the unused-access analyzer |
<!-- END_TF_DOCS -->
