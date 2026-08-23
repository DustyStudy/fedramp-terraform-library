# Customer Responsibility Matrix (CRM)

FedRAMP packages require a Customer Responsibility Matrix — a control-by-
control breakdown of what the cloud provider (AWS) has already handled,
what's shared, and what's entirely on you as the customer/CSP. **This is
not AWS's official CRM.** AWS publishes its own, authoritative CRM as part
of its FedRAMP authorization package, available through AWS Artifact to
customers with the appropriate agreements in place — that's the document
your 3PAO will actually expect to see cited for AWS's inherited controls.

What this file does instead: maps the controls this repo's modules touch
to (a) AWS's general responsibility model for IaaS, (b) what this repo's
modules automate on the customer side, and (c) what remains a manual
process even after you deploy everything here. Use it as a starting point
for your own CRM section, not a substitute for AWS's official one.

| Control ID | AWS (Inherited) | Customer — Automated by This Repo | Customer — Still Manual |
|---|---|---|---|
| AC-2 (Account Management) | Physical/hypervisor-level access control | Password policy, MFA enforcement, root-usage alerting (`moderate/iam-access-control`, `modules/account-baseline`) | Periodic access reviews, offboarding process, account provisioning workflow |
| AC-3 / AC-4 (Access & Flow Enforcement) | Underlying network fabric isolation | SCP guardrails, VPC endpoints (`modules/org-scp-boundary`, `modules/fips-vpc-endpoints`) | Application-layer authorization logic |
| AC-6 (Least Privilege) | N/A | Permission boundary, IAM privilege-escalation denies (`moderate/iam-access-control`, `modules/org-scp-boundary`) | Reviewing that individual role/policy grants are actually least-privilege for your workload |
| AU-2 / AU-3 / AU-6 (Audit Logging & Review) | Physical audit log infrastructure | Org CloudTrail, CIS CloudWatch alarms (`modules/org-cloudtrail`, `moderate/logging-monitoring`) | Someone actually reading the alerts and acting on them; log retention beyond what's configured |
| AU-9 (Protection of Audit Information) | Storage-media-level protection | KMS encryption on trail logs (`modules/org-cloudtrail`) | Enabling S3 Object Lock per-bucket if your SSP requires WORM retention — the SCP only protects a lock that already exists, it doesn't create one |
| CM-6 / CM-8 (Config Management & Inventory) | Hypervisor/hardware configuration | AWS Config conformance pack (`modules/config-conformance-pack`) | Reviewing and remediating Config findings; keeping the conformance pack current as AWS updates it |
| CP-9 / CP-10 (Backup & Recovery) | Underlying storage durability (S3/EBS SLAs) | Backup policy scheduling, Multi-AZ RDS (`modules/org-governance`, `modules/rds-postgres-hardened`) | Actually testing recovery (a backup nobody has restored from is not a validated backup); Vault Lock if immutability is required |
| IA-2 / IA-5 (Authentication) | Underlying identity infrastructure | Account password policy, MFA enforcement | SSO/Identity Center configuration and MFA policy for federated users — outside this repo's scope entirely |
| IR-4 (Incident Handling) | AWS's own incident response for AWS-side events | GuardDuty findings, SNS aggregation (`modules/guardduty-org`, `moderate/incident-response`) | An actual incident response *plan* (who does what, when, escalation paths) and running it — see `COVERAGE-GAPS.md` |
| RA-5 (Vulnerability Scanning) | AWS infrastructure-level scanning | GuardDuty, ECR scan-on-push (`modules/guardduty-org`, `modules/ecr-hardened`) | Monthly authenticated OS/application vulnerability scans required for ConMon — see `CONTINUOUS-MONITORING.md` |
| SC-7 / SC-8 (Boundary & Transmission Protection) | Physical network boundary | VPC Flow Logs, SCP region-lock, TLS enforcement (`modules/network-perimeter-vpc`, `modules/org-scp-boundary`, `modules/rds-postgres-hardened`) | Application-level TLS configuration for anything this repo doesn't touch |
| SC-12 / SC-13 / SC-28 (Cryptography & Encryption at Rest) | Physical key storage hardware (HSMs backing KMS) | KMS CMKs with rotation across nearly every module | Cryptographic module validation for anything outside AWS-managed KMS (e.g., in-application crypto) |
| SI-4 (System Monitoring) | AWS-side network monitoring | GuardDuty, CloudWatch alarms | 24/7 SOC staffing or equivalent monitoring coverage of the alerts this generates |

## Controls this repo doesn't touch at all

PE (Physical and Environmental Protection), PS (Personnel Security), AT
(Awareness and Training), and most of PM (Program Management) are
essentially 100% either AWS-inherited (PE) or pure organizational process
(PS, AT, PM) — no Terraform module addresses them because none should.
See `COVERAGE-GAPS.md` for the full list of what's out of scope and why.
