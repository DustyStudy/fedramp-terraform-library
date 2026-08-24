# FedRAMP 20x

FedRAMP 20x is a fundamentally different assessment model from Rev5's
control baselines — authorizations are validated against a smaller set of
**Key Security Indicators (KSIs)**, many of which are meant to be verified
in a machine-readable way rather than through a traditional control
narrative.

⚠️ **Terminology update (August 2026):** FedRAMP finalized a major
overhaul (the "Consolidated Rules for 2026" / CR26) since this folder was
first written. "FedRAMP Authorization" is now "FedRAMP Certification,"
and Low/Moderate/High baselines are now Certification Classes B/C/D. See
`../docs/FEDRAMP-20X-CHEAT-SHEET.md` for a plain-language rundown of what
changed. The KSI category list below predates CR26 and hasn't been
re-verified against FedRAMP's current published KSI catalog — treat it as
directionally useful, not current.

**Status:** still actively evolving. Before relying on anything in this
folder, check the current guidance at:

- https://www.fedramp.gov/updates/changelog
- https://github.com/FedRAMP (machine-readable FRMR docs and the public
  roadmap)

## Folders (by KSI category) and what already satisfies them

| Folder | KSI Category | Existing modules that already satisfy it |
|---|---|---|
| `ksi-cna/` | Cloud Native Architecture | `modules/eks-hardened`, `modules/ecs-fargate-hardened`, `modules/network-perimeter-vpc` |
| `ksi-iam/` | Identity and Access Management | `moderate/iam-access-control`, `modules/iam-password-policy`, `modules/org-scp-boundary` |
| `ksi-mla/` | Monitoring, Logging and Auditing | `modules/org-cloudtrail`, `modules/guardduty-org`, `modules/security-hub-org`, `moderate/logging-monitoring`, `modules/ecs-fargate-hardened` |
| `ksi-cnbc/` | Configuration and Network Boundary Controls | `modules/config-conformance-pack`, `modules/network-perimeter-vpc`, `modules/fips-vpc-endpoints`, `modules/org-scp-boundary`, `modules/waf-hardened` |
| `ksi-svc/` | Service Configuration | `modules/account-baseline`, `modules/ecr-hardened`, `modules/rds-postgres-hardened`, `modules/ssm-patching-hardened` |
| `ksi-inr/` | Incident Response | `modules/guardduty-org`, `moderate/incident-response` |

This table is a starting point for which existing module to point to when
assembling KSI evidence; it is not a substitute for reading the actual KSI
definitions, since 20x's specific validation method for each indicator may
expect something more precise than "a relevant control exists."
