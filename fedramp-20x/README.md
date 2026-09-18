# FedRAMP 20x

FedRAMP 20x is a fundamentally different assessment model from Rev5's
control baselines — authorizations (now called **Certifications** under
the 2026 rules) are validated against a defined set of **Key Security
Indicators (KSIs)**, many of which are meant to be verified in a
machine-readable way rather than through a traditional control narrative.

## Status: finalized, no longer a pilot

FedRAMP's **Consolidated Rules for 2026** ("CR26") launched 20x Class B as
a generally available certification path, effective **2026-06-24**. As of
that date the KSI structure below is FedRAMP's official set — not a pilot
draft. See:

- https://www.fedramp.gov/2026/reference/20x/b/key-security-indicators/ —
  authoritative source for the table below
- https://www.fedramp.gov/updates/changelog — ongoing changes
- `../docs/FEDRAMP-20X-CHEAT-SHEET.md` — plain-language rundown of the
  2026 terminology changes (Authorization → Certification, Class B/C/D)

**Still verify before submitting evidence:** FedRAMP continues to iterate
inside this structure (RFC-0033/RFC-0034, opened 2026-09-09, cover Class D
development tracks and Technical Advisory Group changes). Check the
changelog link above for anything past this file's last update.

## The 10 KSI clusters (as of the 2026-06-24 Class B launch)

This repo previously tracked 6 categories from FedRAMP 20x's earlier pilot
phase, including `KSI-CNBC` (Configuration and Network Boundary Controls).
**`KSI-CNBC` no longer exists as a cluster.** Its former scope — network
traffic controls moved into `KSI-CNA`, and configuration-drift/encryption
concerns moved into `KSI-SVC`. The folders in this directory now match the
finalized 10-cluster set:

| Folder | KSI Cluster | What it covers | Existing modules that already contribute evidence |
|---|---|---|---|
| `ksi-cna/` | Cloud Native Architecture | Minimal attack surface, network traffic controls, DoS protection, high availability | `modules/eks-hardened`, `modules/ecs-fargate-hardened`, `modules/network-perimeter-vpc`, `modules/waf-hardened`, `modules/fips-vpc-endpoints`, `modules/org-scp-boundary`, `moderate/network-boundary/default-security-group-lockdown` |
| `ksi-iam/` | Identity and Access Management | Account lifecycle automation, least privilege, passwordless/phishing-resistant MFA | `moderate/iam-access-control`, `modules/iam-password-policy`, `modules/account-baseline`, `modules/org-scp-boundary` |
| `ksi-mla/` | Monitoring, Logging, and Auditing | Centralized tamper-resistant logging, persistent log review, config evaluation | `modules/org-cloudtrail`, `modules/guardduty-org`, `modules/security-hub-org`, `moderate/logging-monitoring`, `modules/ecs-fargate-hardened`, `moderate/network-boundary/vpc-flow-logs` |
| `ksi-svc/` | Service Configuration | Automated config-drift detection, secrets/key rotation, encryption, integrity validation | `modules/account-baseline`, `modules/ecr-hardened`, `modules/rds-postgres-hardened`, `modules/ssm-patching-hardened`, `modules/config-conformance-pack`, `modules/eks-hardened`, `moderate/data-protection/kms-cmk-baseline` |
| `ksi-inr/` | Incident Response | Documented IR procedures, after-action reviews, pattern analysis of past incidents | `modules/guardduty-org`, `moderate/incident-response` |
| `ksi-cmt/` | Change Management | Version-controlled, tested deployments; logged and monitored changes | This repo's own CI pipeline (`.github/workflows/ci.yml`) is evidence for the *tooling* side; the documented change-management *procedure* is not something Terraform can provide — see `../docs/COVERAGE-GAPS.md` |
| `ksi-rpl/` | Recovery Planning | Recovery objectives, backup alignment, tested contingency capability | `modules/org-governance` (backup policy schedule/retention) gets partway there; RTO/RPO definition and actual recovery testing are organizational, not infrastructure — see `../docs/COVERAGE-GAPS.md` |
| `ksi-piy/` | Policy and Inventory | Real-time resource inventory, executive support, vulnerability disclosure program | Largely organizational/process; no module here generates a resource inventory automatically. `modules/config-conformance-pack` provides configuration data that could feed one |
| `ksi-scr/` | Supply Chain Risk | Third-party/upstream vulnerability monitoring | `modules/ecr-hardened` (scan-on-push) is the closest existing evidence; broader vendor/dependency risk review is a process, not infra |
| `ksi-ced/` | Cybersecurity Education | Effectiveness review of security training | Out of scope for this repo entirely — a training program, not code. See `../docs/COVERAGE-GAPS.md` |

This table is a starting point for which existing module to point to when
assembling KSI evidence; it is not a substitute for reading the actual KSI
indicator definitions at the fedramp.gov link above, since 20x's specific
validation method for each indicator may expect something more precise
than "a relevant control exists."
