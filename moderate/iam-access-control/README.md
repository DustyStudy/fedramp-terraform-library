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
| Access Analyzer (external access) | AC-3, AC-6 | KSI-IAM-03 |
| Access Analyzer (unused access) | AC-2(3) | KSI-IAM-03 |
| Developer permission boundary | AC-6, AC-6(1) | KSI-IAM-01 |
| Require-MFA IAM group policy | IA-2(1), AC-7 | KSI-IAM-01 |
| Root usage EventBridge rule + SNS | AC-6(5), AU-6 | KSI-IAM-02, KSI-MLA-01 |

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
