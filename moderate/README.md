# FedRAMP Moderate track (Rev5 Class C)

Root configurations for the NIST SP 800-53 Rev5 controls this library
addresses at Rev5 **Class C** (the certification class that loosely aligns
with the former Moderate baseline; FedRAMP says there is no direct
correlation between class and impact level). The `high/` track reuses these
with tighter values.

| Folder | What it deploys |
|---|---|
| `account-baseline/` | `modules/account-baseline`: S3 account public access block, EBS default encryption, IAM password policy (NIST SP 800-63B-4 defaults), default VPC lockdown, AWS Backup vault |
| `data-protection/kms-cmk-baseline/` | Customer-managed KMS key baseline |
| `iam-access-control/` | MFA-enforcement group and permission boundary |
| `incident-response/incident-notifications/` | Aggregated GuardDuty + Security Hub findings topic |
| `logging-monitoring/` | CIS CloudWatch alarms |
| `network-boundary/` | Default security group lockdown, VPC flow logs |
| `org-governance/` | `modules/org-governance`: workload-perimeter SCP, AI opt-out, backup policy |
| `org-scp-boundary/` | `modules/org-scp-boundary`: region lock and security guardrail SCP |

Library-wide docs live in the repository root, not here:
[README](../README.md),
[control mapping](../docs/control-mapping.md),
[NIST 800-53 matrix](../docs/NIST-800-53-REV5-MATRIX.md),
[continuous monitoring](../docs/CONTINUOUS-MONITORING.md),
[coverage gaps](../docs/COVERAGE-GAPS.md),
[20x cheat sheet](../docs/FEDRAMP-20X-CHEAT-SHEET.md), and
[20x KSI cross-reference](../fedramp-20x/README.md).
