# FedRAMP 20x

FedRAMP 20x is a fundamentally different assessment model from Rev5's
control baselines — authorizations are validated against a defined set of
**Key Security Indicators (KSIs)**, many of which are meant to be verified
in a machine-readable way rather than through a traditional control
narrative.

**Terminology update (2026):** FedRAMP finalized a major overhaul (the
"Consolidated Rules for 2026" / CR26). "FedRAMP Authorization" is now
"FedRAMP Certification," and certifications are organized into Classes A–D. Rev5 Classes B/C/D loosely align with the old Low/Moderate/High baselines, but FedRAMP states there is no direct correlation between a Class and an impact level. See `../../docs/FEDRAMP-20X-CHEAT-SHEET.md`
for a plain-language rundown of what changed.

**Update — the KSI category list below is now resolved.** An earlier
version of this note flagged the KSI family structure as genuinely
unsettled, since different 2026 snapshots described anywhere from 9 to 12
top-level themes. As of the **2026-06-24 Class B launch**, FedRAMP's own
reference page (https://www.fedramp.gov/2026/reference/20x/b/key-security-indicators/)
gives a finalized set of **10 clusters**: `AFR`\*, `CED`, `CMT`, `CNA`,
`IAM`, `INR`, `MLA`, `PIY`, `RPL`, `SCR`, `SVC`. Notably, the six-category
model this table was originally built against included `KSI-CNBC`
(Configuration and Network Boundary Controls), which **does not exist**
in the finalized set — its scope split between `KSI-CNA` (network traffic
controls) and `KSI-SVC` (configuration drift, encryption). The table below
has been updated accordingly; see `../../fedramp-20x/README.md` for the
full 10-cluster cross-reference, including the 4 clusters (`CED`, `CMT`,
`PIY`, `RPL`, `SCR`) this table didn't previously track at all.

\* Some third-party summaries list an 11th theme, `KSI-AFR` (Authorization
by FedRAMP — government-specific requirements like collaborative
continuous monitoring and significant-change notification). It does not
appear on FedRAMP's own Class B cluster page as of this writing, so it's
noted here but not given a folder — confirm against the live source before
relying on it either way.

**Status:** still actively evolving in the details even though the
cluster structure is now settled. Before relying on anything in this
folder, check the current guidance at:

- https://www.fedramp.gov/updates/changelog
- https://github.com/FedRAMP/rules (successor to the now-archived
  `FedRAMP/docs`; the machine-readable consolidated rules dataset,
  including KSI definitions, lives at `fedramp-consolidated-rules.json`
  in that repo)

## Folders (by KSI category) and what already satisfies them

| Folder | KSI Category | Existing modules that already satisfy it |
|---|---|---|
| `ksi-cna/` | Cloud Native Architecture | `modules/eks-hardened`, `modules/ecs-fargate-hardened`, `modules/network-perimeter-vpc`, `modules/waf-hardened`, `modules/fips-vpc-endpoints`, `modules/org-scp-boundary` |
| `ksi-iam/` | Identity and Access Management | `moderate/iam-access-control`, `modules/iam-password-policy`, `modules/org-scp-boundary` |
| `ksi-mla/` | Monitoring, Logging and Auditing | `modules/org-cloudtrail`, `modules/guardduty-org`, `modules/security-hub-org`, `moderate/logging-monitoring`, `modules/ecs-fargate-hardened` |
| `ksi-svc/` | Service Configuration | `modules/account-baseline`, `modules/ecr-hardened`, `modules/rds-postgres-hardened`, `modules/ssm-patching-hardened`, `modules/config-conformance-pack` |
| `ksi-inr/` | Incident Response | `modules/guardduty-org`, `moderate/incident-response` |
| `ksi-cmt/` | Change Management | This repo's CI pipeline is evidence for the tooling side; the documented procedure itself is organizational |
| `ksi-rpl/` | Recovery Planning | `modules/org-governance` (backup scheduling) is partial; RTO/RPO definition and recovery testing are organizational |
| `ksi-piy/` | Policy and Inventory | Largely organizational; no module generates an automated resource inventory |
| `ksi-scr/` | Supply Chain Risk | `modules/ecr-hardened` (scan-on-push) is the closest existing evidence |
| `ksi-ced/` | Cybersecurity Education | Out of scope — a training program, not infrastructure |

This table is a starting point for which existing module to point to when
assembling KSI evidence; it is not a substitute for reading the actual KSI
definitions, since 20x's specific validation method for each indicator may
expect something more precise than "a relevant control exists."
