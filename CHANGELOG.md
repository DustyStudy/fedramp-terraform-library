# Changelog

All notable changes to this repo are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Significant infrastructure changes to a live FedRAMP-certified system
fall under FedRAMP's Significant Change Notification (SCN) rules
— see `docs/CONTINUOUS-MONITORING.md`. Keeping this changelog current is
good practice regardless of whether you're tracking against a live
authorization, since it mirrors the change-documentation discipline
FedRAMP expects.

## [Unreleased]

### Fixed (FedRAMP accuracy audit, 2026-09-26)
- **IA-5 password policy now follows NIST SP 800-63B-4**, which FedRAMP's IA-5
  guidance points to. `iam-password-policy` and `account-baseline` default to a
  15-character minimum, no composition rules, and no periodic expiry;
  800-63B-4 says verifiers "SHALL NOT impose other composition rules" and "SHALL
  NOT require subscribers to change passwords periodically". Composition rules
  and `max_password_age` are opt-in variables. Removed variable descriptions
  claiming "FedRAMP requires >= 14 / <= 60 or 90 days / >= 24" (FedRAMP assigns
  none of those). **Behavior change:** existing deployments drop composition
  rules and expiry unless you set the new variables.
- **Backup policy couldn't run:** it targeted `FedRAMPComplianceVault`, which
  nothing created. `account-baseline` now creates it (CMK-encrypted, rotation
  on; `create_backup_vault`), and `org-governance` takes `backup_vault_name`.
  Added a real cross-region copy (`copy_destination_region`), because the policy
  said "cross-region compliance" but had no copy action. Corrected
  `backup_regions` (it sets where the plan runs, not replication) and the
  retention description (FedRAMP assigns no CP-9 value). Added a >= 120-day
  retention validation for AWS's cold-storage minimum.
- **FIPS endpoints:** the `high/` roots now set `use_fips_endpoint = true`
  (variable), since Class D MUST use validated crypto (`CMU-CSO-UVM`). Corrected
  the claim that only kms/ec2/sts have FIPS VPC endpoint service names: AWS
  lists many more (s3-fips, sqs-fips, dynamodb-fips, ...).
- Rewrote `docs/CONTINUOUS-MONITORING.md` for CR26 (quarterly CCM, VDR
  timeframes, SCN); it still described the pre-2026 monthly POA&M model.
  `POAM-TEMPLATE.md` is marked legacy (VER replaces provider POA&Ms).
- Checkov CKV_AWS_144 skips no longer claim replication is "handled" by the org
  backup policy or a DR baseline.
- Removed stale copies `moderate/docs/` and `moderate/fedramp-20x/` (they
  floated a nonexistent `KSI-AFR` cluster), and replaced `moderate/README.md`,
  an old copy of the root README, with a Moderate-track README.
- README: the High track description now matches what it changes.
- **`guardduty-org` failed `terraform validate` on every AWS provider v6
  release** the module allows: v6 removed `auto_enable` and made
  `auto_enable_organization_members` required. The module now sets it from a
  new `auto_enable_organization_members` variable (default `NEW`, matching the
  old behavior; `ALL` also covers existing members). `auto_enable = false`
  must now be paired with `"NONE"`, and a precondition says so. This also
  fixes `examples/management-account-baseline`.


### Security
- `modules/org-cloudtrail`: the trail bucket policy now pins CloudTrail's
  write and ACL-check statements to this trail's ARN (`aws:SourceArn`), so
  another account's trail can no longer deliver into the audit bucket, and
  denies non-TLS access. The access-log bucket now uses SSE-S3 (S3 server
  access logging cannot deliver to an SSE-KMS bucket, so logs were being
  dropped silently) and has the log-delivery and TLS-only bucket policy it
  was missing. The alert topic gains the topic policy CloudTrail requires,
  and the key policy allows `kms:Decrypt` for it.
- `modules/config-conformance-pack`: same access-log bucket fix (SSE-S3 +
  log-delivery policy), and TLS-only policies on both buckets.
- `modules/ssm-patching-hardened`: TLS-only bucket policy on patch logs.
- `modules/waf-hardened`: WAF logging now redacts the `authorization` and
  `cookie` headers so credentials/session tokens are not written to the
  log group in cleartext.
- `modules/eks-hardened`: control-plane logs go to a module-managed,
  KMS-encrypted log group with bounded retention (new
  `log_retention_days`, default 365). Previously EKS auto-created an
  unencrypted, never-expiring group.
- `modules/guardduty-org`, `moderate/incident-response/incident-notifications`,
  `moderate/logging-monitoring`, `moderate/iam-access-control`: SNS topics
  moved off the AWS-managed `alias/aws/sns` key, which EventBridge and
  CloudWatch cannot publish to (notifications were silently dropped), onto
  customer-managed keys. Topic policies now carry `aws:SourceArn` /
  `aws:SourceAccount` conditions.
- `moderate/iam-access-control`: the root-usage alert was a CloudWatch
  alarm on a custom metric nothing emitted, so it could never fire. It is
  now an EventBridge rule on root activity, as the README describes.
- `modules/org-scp-boundary`: also denies the current-name GuardDuty and
  Security Hub administrator-disassociation actions
  (`...FromAdministratorAccount`, distinct from the legacy `...FromMasterAccount`
  names), member deletion/stop-monitoring, `securityhub:BatchDisableStandards`
  and `cloudtrail:PutEventSelectors`.
- CI: third-party actions pinned to commit SHAs, checkouts no longer
  persist the token, and `security-events: write` is scoped to the one job
  that uploads SARIF.

### Added
- Compliance documentation: Customer Responsibility Matrix
  (`docs/CUSTOMER-RESPONSIBILITY-MATRIX.md`), coverage gap analysis
  (`docs/COVERAGE-GAPS.md`), POA&M starter template
  (`docs/POAM-TEMPLATE.md`), and continuous monitoring mapping
  (`docs/CONTINUOUS-MONITORING.md`)
- `docs/FEDRAMP-20X-CHEAT-SHEET.md` — plain-language rundown of the 2026
  "Consolidated Rules" terminology and timeline changes. This file was
  already referenced from two READMEs before it existed; it's now real.
- `fedramp-20x/ksi-cmt/`, `ksi-rpl/`, `ksi-piy/`, `ksi-scr/`, `ksi-ced/` —
  5 new KSI category folders, matching the finalized 10-cluster structure
  FedRAMP published for the 2026-06-24 20x Class B launch

### Changed
- Retired `fedramp-20x/ksi-cnbc/`: `KSI-CNBC` (Configuration and Network
  Boundary Controls) does not exist in FedRAMP's finalized 2026 KSI
  structure. Its scope split between `KSI-CNA` (network/traffic controls)
  and `KSI-SVC` (configuration drift, encryption). Remapped every
  `docs/control-mapping.md` entry that previously pointed to `KSI-CNBC-*`,
  and replaced placeholder numeric KSI IDs (`KSI-MLA-01`, etc.) across
  that file with FedRAMP's actual mnemonic indicator codes
  (`KSI-MLA-OSM`, etc.) where a page-level source could confirm them

## 2026-08-23

### Added
- 11 additional modules: `account-baseline`, `ecr-hardened`,
  `ecs-fargate-hardened`, `eks-hardened`, `fips-vpc-endpoints`,
  `network-perimeter-vpc`, `org-governance`, `org-scp-boundary`,
  `rds-postgres-hardened`, `ssm-patching-hardened`, `waf-hardened`
- `docs/NIST-800-53-REV5-MATRIX.md` — control-ID-oriented mapping across
  all modules
- Hardened CI pipeline (`ci.yml`): Gitleaks secret scanning, `terraform
  fmt`/tflint, Checkov (blocking) + Trivy (reporting)

### Fixed
- KMS key policies on `waf-hardened`, `ecs-fargate-hardened`,
  `network-perimeter-vpc`, and `ssm-patching-hardened` were missing the
  service-principal (or writer-role) grant needed for the encrypted
  resource to actually function — these are functional bugs, not just
  hardening gaps, and would have failed at deploy/runtime
- `fips-vpc-endpoints` defaulted to services with no genuine FIPS-suffixed
  VPC endpoint name, meaning the module silently created ordinary
  interface endpoints while being labeled FIPS-specific; corrected to
  only auto-suffix the services that actually have one (`kms`, `ec2`,
  `sts`), with the rest split into a separate, honestly-labeled variable
- `docs/NIST-800-53-REV5-MATRIX.md` contained three verified-inaccurate
  claims (S3 Object Lock enforcement, backup vault immutability, non-root
  container UID enforcement) that didn't match any module's actual code —
  rewritten using only claims checked directly against the implementation

## Initial release

- Core modules: `org-cloudtrail`, `config-conformance-pack`,
  `guardduty-org`, `security-hub-org`, `iam-password-policy`
- `moderate/iam-access-control`, `moderate/logging-monitoring`
- `high/example-tfvars` illustrating the parameter-override pattern
- `fedramp-20x/` KSI cross-reference
- Initial CI (`terraform fmt`/validate, tflint, Checkov)
