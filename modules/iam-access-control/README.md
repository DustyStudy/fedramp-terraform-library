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
- The permission boundary is a ceiling, not a grant — attach it via
  `permissions_boundary` when creating roles/users; it doesn't do anything
  by itself until referenced.
- The `DenyPrivilegeEscalationViaIAM` statement covers IAM-only escalation
  paths. It does not cover `iam:PassRole` combined with a compute service —
  that needs a resource-scoped `PassRole` condition or an SCP, layered on
  top of this boundary.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| analyzer_type | Use ORGANIZATION if deploying from the delegated Access Analyzer administrator account to cover all member accounts; ACCOUNT for a single-account deployment. | `string` | `"ACCOUNT"` | no |
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
