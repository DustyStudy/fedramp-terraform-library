# Control Mapping

Cross-reference of modules to the NIST SP 800-53 Rev5 control IDs
(Moderate/High) or FedRAMP 20x Key Security Indicator IDs they help
implement. This is a starting point for your control implementation
narrative — always verify against your current SSP language and your 3PAO's
expectations.

**20x KSI column note (updated for CR26):** the IDs below use FedRAMP's
finalized mnemonic indicator codes (e.g. `KSI-MLA-OSM`) from the
2026-06-24 Class B ruleset, not the numeric placeholders (`KSI-MLA-01`)
used in earlier drafts of this file. `KSI-CNBC` no longer exists as a
cluster — anything previously mapped to it has been remapped to `KSI-CNA`
(network/traffic controls) or `KSI-SVC` (configuration/encryption). See
`fedramp-20x/README.md` for the full cluster list and sourcing. These are
still best-effort module-to-indicator mappings, not a citation of
FedRAMP's own crosswalk — verify each one against the live indicator
definitions before using it in an SSP.

## modules/ (shared baseline, used by all three tracks)

| Module | Rev5 Controls | 20x KSI |
|---|---|---|
| `org-cloudtrail` | AU-2, AU-3, AU-6, AU-11, AU-12 | KSI-MLA-OSM, KSI-MLA-LET |
| `config-conformance-pack` | CM-2, CM-6, CM-8, CA-7 | KSI-SVC-ACM, KSI-MLA-EVC |
| `guardduty-org` | SI-4, IR-4 | KSI-CNA-EIS, KSI-INR-RPI |
| `security-hub-org` | CA-7, RA-5, SI-4 | KSI-MLA-EVC, KSI-CNA-EIS |
| `iam-password-policy` | IA-5, AC-2, AC-7 | KSI-IAM-APM, KSI-IAM-AAM |

**Note on native resources vs. workarounds:** `iam-password-policy` and
`guardduty-org` use native Terraform resources (`aws_iam_account_password_policy`,
`aws_guardduty_organization_configuration`) — no custom scripting needed,
unlike the CloudFormation version of this library, where both required a
Lambda-backed custom resource because no native CFN resource type exists
for either.

## modules/ (additional infrastructure modules)

| Module | Rev5 Controls | 20x KSI | Notes |
|---|---|---|---|
| `account-baseline` | AC-2, IA-5, MP-2, CM-7, SC-28 | KSI-IAM-APM, KSI-SVC-SIN | Account password policy, EBS default encryption, S3 account public access block, optional default-VPC/SG lockdown |
| `ecr-hardened` | RA-5, SC-28, SC-12 | KSI-SVC-SIN, KSI-SVC-VRI | KMS-encrypted repository, tag immutability, scan-on-push. Whoever pushes/pulls images needs KMS grants added separately — see module README |
| `ecs-fargate-hardened` | AU-12, SC-13 | KSI-MLA-LET | Container Insights, KMS-encrypted logs + ECS Exec session logging |
| `eks-hardened` | AU-2, SC-7, SC-13 | KSI-MLA-LET, KSI-CNA-RNT, KSI-SVC-SIN | KMS secrets envelope encryption, all 5 control-plane log types, private-only API endpoint |
| `fips-vpc-endpoints` | AC-3, SC-7, SC-8, SC-13 | KSI-CNA-RNT, KSI-SVC-VCM | Only `kms`, `ec2`, `sts` have genuine FIPS-suffixed endpoint names — see module README for why the rest don't |
| `network-perimeter-vpc` | AU-12, SC-7, CM-7 | KSI-CNA-RNT, KSI-CNA-ULN, KSI-MLA-LET | 3-tier VPC, Flow Logs to KMS-encrypted CloudWatch Logs, default SG locked to zero rules |
| `org-governance` | AC-2, AC-4, AU-9, CP-9, MP-2 | KSI-IAM-ELP, KSI-RPL-ABO | Workload-perimeter SCP, AI-services opt-out policy, centralized backup policy (schedule/retention only — no vault lock) |
| `org-scp-boundary` | AC-3, AC-4, AC-6, SC-7, SC-8 | KSI-CNA-RNT, KSI-CNA-ULN, KSI-IAM-ELP | Region-lock SCP, deny-disable-security-services, insecure-transport deny |
| `rds-postgres-hardened` | CP-9, CP-10, SC-8, SC-12, SC-28, IA-5 | KSI-SVC-SIN, KSI-SVC-VCM | Multi-AZ PostgreSQL, `force_ssl`, KMS storage encryption, managed master password |
| `ssm-patching-hardened` | SI-2, AU-12 | KSI-SVC-EIS | Automated patch baseline (7-day critical approval), weekly maintenance window, KMS-encrypted output logs |
| `waf-hardened` | SC-5, SI-3, AU-2 | KSI-CNA-RVP, KSI-CNA-MAT | Regional WAFv2 with 3 AWS-managed rule groups + rate limiting, KMS-encrypted logging |

See `docs/NIST-800-53-REV5-MATRIX.md` for a control-ID-oriented view across
all of the above with implementation detail per control.

## moderate/

| Folder | Rev5 Control Family |
|---|---|
| `logging-monitoring/` | AU (Audit and Accountability) |
| `iam-access-control/` | AC (Access Control), IA (Identification and Authentication) |
| `network-boundary/` | SC (System and Communications Protection) |
| `data-protection/` | SC-13, SC-28, MP (Media Protection) |
| `incident-response/` | IR (Incident Response) |

### logging-monitoring

All 14 filter patterns are copied verbatim from AWS's Security Hub CSPM
documentation — see `moderate/logging-monitoring/README.md` for the full
per-alarm control mapping.

### iam-access-control

Access Analyzer, permission boundary, enforced-MFA group, root usage
alerting — see `moderate/iam-access-control/README.md` for the full
resource-level control mapping.

### network-boundary/

| Module | Rev5 Controls | 20x KSI |
|---|---|---|
| `vpc-flow-logs` | SC-7, AU-2, AU-12 | KSI-CNA-ULN, KSI-MLA-LET |
| `default-security-group-lockdown` | SC-7, CM-7 | KSI-CNA-MAT |

**Note:** `default-security-group-lockdown` uses the native
`aws_default_security_group` resource — no custom scripting needed,
unlike the CloudFormation version of this library, where the same task
required a Lambda-backed custom resource because CFN can't otherwise
manage default-SG rules directly.

### data-protection/

| Module | Rev5 Controls | 20x KSI |
|---|---|---|
| `kms-cmk-baseline` | SC-12, SC-13, SC-28 | KSI-SVC-ASM |

### incident-response/

| Module | Rev5 Controls | 20x KSI |
|---|---|---|
| `incident-notifications` | IR-4, IR-5, IR-6 | KSI-INR-RIR, KSI-INR-AAR |

*(Fill in remaining folder mappings as modules are added.)*

## high/

High reuses the `moderate/` modules with tighter variable values via
`.tfvars` overrides rather than duplicating module code. Only add a
module here if it diverges *structurally* from its Moderate counterpart
(not just variable values) — e.g. FIPS 140-3 validated endpoint
enforcement, additional audit event types required at High.

## fedramp-20x/

FedRAMP 20x's KSI clusters were finalized as part of the "Consolidated
Rules for 2026," effective 2026-06-24 (20x Class B) — see
https://www.fedramp.gov/2026/reference/20x/b/key-security-indicators/ for
the authoritative source and https://www.fedramp.gov/updates/changelog for
anything more recent. The 6-category set this repo originally tracked
included `KSI-CNBC`, which does **not** exist in the finalized structure;
its scope split across `KSI-CNA` and `KSI-SVC` below.

| Folder | KSI Category |
|---|---|
| `ksi-cna/` | Cloud Native Architecture |
| `ksi-iam/` | Identity and Access Management |
| `ksi-mla/` | Monitoring, Logging and Auditing |
| `ksi-svc/` | Service Configuration |
| `ksi-inr/` | Incident Response |
| `ksi-cmt/` | Change Management |
| `ksi-rpl/` | Recovery Planning |
| `ksi-piy/` | Policy and Inventory |
| `ksi-scr/` | Supply Chain Risk |
| `ksi-ced/` | Cybersecurity Education |

See `fedramp-20x/README.md` for a cross-reference of which existing
`modules/` and `moderate/` code already satisfy each category, and
`FEDRAMP-20X-CHEAT-SHEET.md` for the broader 2026 terminology/timeline
changes.
