# FedRAMP Moderate

Modules here target the NIST SP 800-53 Rev5 **Moderate** baseline (~325
controls). Start with `../modules/` for the shared account-level baseline
(CloudTrail, Config, GuardDuty, Security Hub, IAM password policy) — those
underpin nearly every control family below.

| Folder | Control Family | Status |
|---|---|---|
| `logging-monitoring/` | AU | 14 CIS/Security Hub CloudWatch metric-filter + alarm pairs, built on `modules/org-cloudtrail`'s log group |
| `iam-access-control/` | AC, IA | Access Analyzer (external + unused access), permission boundary, enforced-MFA group, root usage alerting |
| `account-baseline/` | AC-2, IA-5, MP-2 | Calls `modules/account-baseline` with Moderate password-policy values |
| `org-governance/` | AC-2, AC-4, CP-9 | Calls `modules/org-governance` with a 365-day backup retention |
| `org-scp-boundary/` | AC-3, AC-4, SC-7 | Calls `modules/org-scp-boundary` with the Moderate policy name |
| `network-boundary/` | SC | Not yet built for Terraform (see the CFN repo's equivalent for the pattern to port) |
| `data-protection/` | SC-13, SC-28, MP | Not yet built for Terraform |
| `incident-response/` | IR | Not yet built for Terraform |

See `../docs/control-mapping.md` for module-to-control detail.
