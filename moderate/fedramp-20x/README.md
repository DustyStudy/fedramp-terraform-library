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
changed.

⚠️ **On the KSI category list below specifically:** I looked into
updating this against FedRAMP's current official KSI catalog and found
something worth being upfront about — the family structure itself is
genuinely unsettled. Different snapshots of FedRAMP's own machine-readable
KSI document (`FRMR.KSI.key-security-indicators.json` in
[github.com/FedRAMP/docs](https://github.com/FedRAMP/docs)), and
third-party summaries of it from different months in 2026, describe
anywhere from 9 to 12 top-level KSI themes and anywhere from 46 to 63
individual indicators. One February 2026 analysis of the actual JSON
schema lists 11 themes (`AFR`, `CED`, `CMT`, `CNA`, `IAM`, `INR`, `MLA`,
`PIY`, `RPL`, `SCC`, `UDC`) — several of which don't correspond to
anything in the six-category model this table was originally built
against, and I couldn't confidently determine what some of those newer
codes (`CMT`, `PIY`, `SCC`, `UDC`) actually stand for from the sources
available to me. Rather than guess, I've left the table below as-is: the
six categories are broad, durable **engineering** groupings (identity,
logging, network config, etc.) that still make sense as a map to this
repo's modules, but they should not be read as a current, authoritative
list of FedRAMP's official KSI family names. Before using this for actual
KSI evidence-mapping, check the live JSON file directly, or use a tool
built to query it (e.g. the community-built FedRAMP Docs MCP server) —
don't rely on this table's category names matching what a 3PAO or
FedRAMP reviewer expects to see.

**Status:** still actively evolving. Before relying on anything in this
folder, check the current guidance at:

- https://www.fedramp.gov/updates/changelog
- https://github.com/FedRAMP/docs (the actual machine-readable KSI
  definitions live at `markdown/FRMR.KSI.key-security-indicators.md` and
  `FRMR.KSI.key-security-indicators.json` in this repo)

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
