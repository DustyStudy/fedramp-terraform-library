# Changelog

All notable changes to this repo are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Significant infrastructure changes to a live FedRAMP-authorized system
require going through FedRAMP's Significant Change Request (SCR) process
— see `docs/CONTINUOUS-MONITORING.md`. Keeping this changelog current is
good practice regardless of whether you're tracking against a live
authorization, since it mirrors the change-documentation discipline
FedRAMP expects.

## [Unreleased]

### Added
- Compliance documentation: Customer Responsibility Matrix
  (`docs/CUSTOMER-RESPONSIBILITY-MATRIX.md`), coverage gap analysis
  (`docs/COVERAGE-GAPS.md`), POA&M starter template
  (`docs/POAM-TEMPLATE.md`), and continuous monitoring mapping
  (`docs/CONTINUOUS-MONITORING.md`)

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
