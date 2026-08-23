# Control Mapping

Cross-reference of modules to the NIST SP 800-53 Rev5 control IDs
(Moderate/High) or FedRAMP 20x Key Security Indicator IDs they help
implement. This is a starting point for your control implementation
narrative — always verify against your current SSP language and your 3PAO's
expectations.

## modules/ (shared baseline, used by all three tracks)

| Module | Rev5 Controls | 20x KSI |
|---|---|---|
| `org-cloudtrail` | AU-2, AU-3, AU-6, AU-11, AU-12 | KSI-MLA-01, KSI-MLA-02 |
| `config-conformance-pack` | CM-2, CM-6, CM-8, CA-7 | KSI-CNBC-01, KSI-CNBC-02 |
| `guardduty-org` | SI-4, IR-4 | KSI-MLA-03, KSI-INR-01 |
| `security-hub-org` | CA-7, RA-5, SI-4 | KSI-MLA-04 |
| `iam-password-policy` | IA-5, AC-2, AC-7 | KSI-IAM-01 |

**Note on native resources vs. workarounds:** `iam-password-policy` and
`guardduty-org` use native Terraform resources (`aws_iam_account_password_policy`,
`aws_guardduty_organization_configuration`) — no custom scripting needed,
unlike the CloudFormation version of this library, where both required a
Lambda-backed custom resource because no native CFN resource type exists
for either.

## modules/ (additional infrastructure modules)

| Module | Rev5 Controls | 20x KSI | Notes |
|---|---|---|---|
| `account-baseline` | AC-2, IA-5, MP-2, CM-7, SC-28 | KSI-IAM-01, KSI-SVC-01 | Account password policy, EBS default encryption, S3 account public access block, optional default-VPC/SG lockdown |
| `ecr-hardened` | RA-5, SC-28, SC-12 | KSI-SVC-02 | KMS-encrypted repository, tag immutability, scan-on-push. Whoever pushes/pulls images needs KMS grants added separately — see module README |
| `ecs-fargate-hardened` | AU-12, SC-13 | KSI-MLA-01 | Container Insights, KMS-encrypted logs + ECS Exec session logging |
| `eks-hardened` | AU-2, SC-7, SC-13 | KSI-MLA-01, KSI-CNBC-02 | KMS secrets envelope encryption, all 5 control-plane log types, private-only API endpoint |
| `fips-vpc-endpoints` | AC-3, SC-7, SC-8, SC-13 | KSI-CNBC-02 | Only `kms`, `ec2`, `sts` have genuine FIPS-suffixed endpoint names — see module README for why the rest don't |
| `network-perimeter-vpc` | AU-12, SC-7, CM-7 | KSI-CNBC-02, KSI-MLA-01 | 3-tier VPC, Flow Logs to KMS-encrypted CloudWatch Logs, default SG locked to zero rules |
| `org-governance` | AC-2, AC-4, AU-9, CP-9, MP-2 | KSI-IAM-02, KSI-CNBC-01 | Workload-perimeter SCP, AI-services opt-out policy, centralized backup policy (schedule/retention only — no vault lock) |
| `org-scp-boundary` | AC-3, AC-4, AC-6, SC-7, SC-8 | KSI-CNBC-01, KSI-CNBC-02 | Region-lock SCP, deny-disable-security-services, insecure-transport deny |
| `rds-postgres-hardened` | CP-9, CP-10, SC-8, SC-12, SC-28, IA-5 | KSI-SVC-02 | Multi-AZ PostgreSQL, `force_ssl`, KMS storage encryption, managed master password |
| `ssm-patching-hardened` | SI-2, AU-12 | KSI-SVC-01 | Automated patch baseline (7-day critical approval), weekly maintenance window, KMS-encrypted output logs |
| `waf-hardened` | SC-5, SI-3, AU-2 | KSI-CNBC-02 | Regional WAFv2 with 3 AWS-managed rule groups + rate limiting, KMS-encrypted logging |

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

*(Fill in remaining folder mappings as modules are added.)*

## high/

High reuses the `moderate/` modules with tighter variable values via
`.tfvars` overrides rather than duplicating module code. Only add a
module here if it diverges *structurally* from its Moderate counterpart
(not just variable values) — e.g. FIPS 140-3 validated endpoint
enforcement, additional audit event types required at High.

## fedramp-20x/

FedRAMP 20x KSI categories (subject to change as FedRAMP finalizes guidance —
see https://www.fedramp.gov/updates/changelog for the current status):

| Folder | KSI Category |
|---|---|
| `ksi-cna/` | Cloud Native Architecture |
| `ksi-iam/` | Identity and Access Management |
| `ksi-mla/` | Monitoring, Logging and Auditing |
| `ksi-cnbc/` | Configuration and Network Boundary Controls |
| `ksi-svc/` | Service Configuration |
| `ksi-inr/` | Incident Response |

See `fedramp-20x/README.md` for a cross-reference of which existing
`modules/` and `moderate/` code already satisfy each category.
