# FedRAMP Terraform Library

[![CI](https://github.com/DustyStudy/fedramp-terraform-library/actions/workflows/ci.yml/badge.svg)](https://github.com/DustyStudy/fedramp-terraform-library/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Reusable Terraform modules that implement common controls and security
patterns for organizations pursuing **FedRAMP Moderate**, **FedRAMP
High**, or **FedRAMP 20x** authorization.

Choose a [deployment track](#why-three-separate-tracks), [find a control implementation](docs/control-mapping.md), or [deploy a worked example](examples/README.md).

**At a glance**

- **Problem:** FedRAMP control implementations get rebuilt by hand for every
  system, and a plan that passes `terraform validate` can still grant too much.
- **Approach:** 24 shared modules, with root configurations for the Moderate and High
  tracks, plus a map from the 10 FedRAMP 20x KSI clusters to those modules.
  FIPS endpoints and partition-aware ARNs for GovCloud.
- **Verification:** 253 `terraform test` runs assert the rendered IAM and
  bucket policies at plan time, and 437 pytest tests cover the module
  Lambdas (local run of the 4.1.0 release branch, 2026-11-24; CI reruns both
  on every PR). Checkov, Trivy and Gitleaks run on every PR. See
  [what is verified, and what is not](docs/PROOF.md).
- **Live use:** sixteen modules were deployed to a real 4-account
  organization and checked with real API calls, including alarm,
  finding-routing and auditor paths end to end, an image push, requests
  through the web ACL and TLS and IAM sign-in to the database. See the
  [live proof](docs/LIVE-PROOF.md). Earlier, a read-only
  `trust-policy-auditor` run there found a GitHub OIDC deploy role that
  any branch could assume.

## ⚠️ Disclaimer

These modules support the *implementation* of security controls. They do
**not**, by themselves, constitute a FedRAMP authorization. An Authority to
Operate (ATO) requires an agency sponsor, a 3PAO (Third Party Assessment
Organization) assessment, and an approved System Security Plan (SSP). Treat
this repo as a starting point for your control implementation evidence, not
a substitute for the assessment process.

Modules are provided as-is with no warranty. Review every variable,
resource, and IAM policy before applying to any environment, and validate
against your organization's current SSP and your 3PAO's expectations.

## Why three separate tracks?

- **`moderate/`** and **`high/`** map to the NIST SP 800-53 Rev5 control
  baselines. High reuses Moderate's modules with tighter values rather
  than duplicating module code: longer log and backup retention, a
  dedicated EBS CMK, and a 16-character password minimum. Both tracks
  send AWS API calls to FIPS endpoints (see [FIPS endpoints](#fips-endpoints)).
- **`fedramp-20x/`** is *not* a control baseline. FedRAMP 20x
  certifications are validated against machine-readable **Key Security
  Indicators (KSIs)**: a fundamentally different assessment model.
  FedRAMP's "Consolidated Rules for 2026" moved 20x from pilot to a
  generally available certification path (effective 2026-06-24) and
  finalized 10 KSI clusters. See `fedramp-20x/README.md` for the current
  cluster list and a cross-reference of which existing modules already
  satisfy each one.

## How the pieces fit

```mermaid
flowchart LR
  subgraph mgmt["Management / delegated admin account"]
    scp["org-scp-boundary<br/>org-governance"]
    trail["org-cloudtrail"]
    gd["guardduty-org"]
    sh["security-hub-org"]
  end
  subgraph member["Every member account, every region"]
    base["account-baseline<br/>iam-password-policy"]
    cfg["config-conformance-pack"]
    wl["Workload modules<br/>eks / ecs / rds / waf / vpc"]
  end
  scp -- "SCPs deny disabling logging<br/>and unapproved regions" --> member
  member -- "API activity" --> trail
  cfg -- "config history" --> s3[("KMS-encrypted<br/>S3 archive")]
  trail --> s3
  gd -- "findings >= Medium" --> sns["SNS / incident response"]
  member -- "findings" --> sh
```

## Structure

```
modules/              Shared baseline modules used across all three tracks
moderate/             Rev5 Moderate baseline, by control family
high/                 Rev5 High: reuses moderate/ with tfvars overrides
fedramp-20x/          KSI-to-module cross-reference, no Terraform (CNA, IAM, MLA, SVC, INR, CMT, RPL, PIY, SCR, CED)
docs/                 Control mapping, verification record, compliance guides
examples/             Management-account and member-account baselines composed from the modules
proof/                Live-test fixtures, not reference code (see proof/README.md)
tests/                pytest and SQL fixtures for the module Lambdas
```

## Modules

The catalog includes 24 shared modules under `modules/` and three components under `moderate/`.

| Module | What it does |
|---|---|
| [`org-cloudtrail`](modules/org-cloudtrail/README.md) | Organization-wide CloudTrail, KMS-encrypted, with a dedicated access-log bucket |
| [`config-conformance-pack`](modules/config-conformance-pack/README.md) | AWS Config recorder + encrypted delivery channel, optional FedRAMP Moderate conformance pack |
| [`guardduty-org`](modules/guardduty-org/README.md) | GuardDuty with organization auto-enrollment, findings routed to SNS |
| [`security-hub-org`](modules/security-hub-org/README.md) | Security Hub with default standards + organization auto-enrollment |
| [`iam-password-policy`](modules/iam-password-policy/README.md) | Account-wide IAM password policy |
| [`identity-center-access-auditor`](modules/identity-center-access-auditor/README.md) | Daily detective audit of IAM Identity Center: admin or wildcard permission sets, direct-to-user assignments, unused permission sets |
| [`trust-policy-auditor`](modules/trust-policy-auditor/README.md) | Daily detective audit of who can reach in from outside: OIDC trust without a pinned `sub`/`aud`, cross-account and `"*"` trust, open Lambda function policies, RAM shares outside the organization. Single account or organization-wide |
| [`rds-access-auditor`](modules/rds-access-auditor/README.md) | Daily detective audit of RDS and Aurora access: public exposure with open security groups, unmanaged master passwords, IAM auth off, TLS not enforced, IAM `rds-db:connect` as any user or the master user. Ships a read-only SQL audit of PostgreSQL role grants |
| [`secret-access-burst-detector`](modules/secret-access-burst-detector/README.md) | Scheduled detective check of CloudTrail logs: reports a principal with a burst of denied API calls and a successful secret or parameter read in the same window. Off by default |
| [`account-baseline`](modules/account-baseline/README.md) | EBS default encryption, S3 account public access block, optional default-VPC/SG lockdown, backup vault with opt-in Vault Lock and deny-delete vault policy |
| [`ecr-hardened`](modules/ecr-hardened/README.md) | KMS-encrypted ECR repository, tag immutability, scan-on-push |
| [`ecs-fargate-hardened`](modules/ecs-fargate-hardened/README.md) | ECS cluster with Container Insights and KMS-encrypted logging (incl. ECS Exec) |
| [`eks-hardened`](modules/eks-hardened/README.md) | EKS cluster with KMS secrets envelope encryption, full control-plane logging, private-only endpoint |
| [`fips-vpc-endpoints`](modules/fips-vpc-endpoints/README.md) | VPC interface endpoints: see the module's `variables.tf` for which services genuinely have FIPS-suffixed endpoints and which don't |
| [`network-perimeter-vpc`](modules/network-perimeter-vpc/README.md) | 3-tier VPC with KMS-encrypted Flow Logs and a locked-down default security group |
| [`org-governance`](modules/org-governance/README.md) | Workload-perimeter SCP, AI-services opt-out policy, centralized backup policy |
| [`org-scp-boundary`](modules/org-scp-boundary/README.md) | Region-lock SCP, security-service protection, insecure-transport deny, MFA-removal deny, optional IMDSv2 enforcement |
| [`rds-postgres-hardened`](modules/rds-postgres-hardened/README.md) | Multi-AZ PostgreSQL with enforced TLS, KMS encryption, managed master password |
| [`stale-account-detector`](modules/stale-account-detector/README.md) | Reports unused IAM credentials, roles, Identity Center access and idle accounts across the organization |
| [`ssm-patching-hardened`](modules/ssm-patching-hardened/README.md) | Automated patch baseline, weekly maintenance window, KMS-encrypted patch logs |
| [`waf-hardened`](modules/waf-hardened/README.md) | Regional WAFv2 with AWS-managed rule groups, rate limiting, KMS-encrypted logging |
| [`iam-access-control`](modules/iam-access-control/README.md) | Access Analyzer, permission boundary, enforced-MFA group, root usage alerting |
| [`logging-monitoring`](modules/logging-monitoring/README.md) | 14 CIS/Security Hub CloudWatch metric-filter + alarm pairs, plus IAM and Identity Center MFA-change alarms and an optional unexpected-secret-read alarm |
| [`moderate/network-boundary/vpc-flow-logs`](moderate/network-boundary/vpc-flow-logs/README.md) | VPC Flow Logs to encrypted S3, for an existing VPC |
| [`moderate/network-boundary/default-security-group-lockdown`](moderate/network-boundary/default-security-group-lockdown/README.md) | Strips all rules from an existing VPC's default security group (native resource; no custom scripting needed, unlike CFN) |
| [`moderate/data-protection/kms-cmk-baseline`](moderate/data-protection/kms-cmk-baseline/README.md) | Reusable customer-managed KMS key for encryption at rest |
| [`incident-notifications`](modules/incident-notifications/README.md) | Aggregated SNS topic for high-severity GuardDuty/Security Hub findings |

See `docs/control-mapping.md` for the NIST 800-53/20x KSI mapping per
module, and `docs/NIST-800-53-REV5-MATRIX.md` for the same information
organized by control ID instead.

## Examples

Every module above is documented in isolation. **`examples/`** shows a
realistic set of them composed into an actual management-account and
member-account baseline, including two duplicate-resource conflicts
that only showed up once modules were wired together, and how to avoid
them.

## Compliance documentation beyond control mapping

Passing a FedRAMP audit takes more than deployed infrastructure. These
docs are aimed at that gap directly:

- **`docs/CUSTOMER-RESPONSIBILITY-MATRIX.md`**: what AWS already covers,
  what this repo automates, what's still a manual process
- **`docs/COVERAGE-GAPS.md`**: control families and requirements this
  repo genuinely cannot address (personnel security, training, the SSP
  itself, tested IR/contingency plans, and more), stated plainly rather
  than left implicit
- **`docs/CONTINUOUS-MONITORING.md`**: how this repo's modules feed
  FedRAMP's CR26 continuous monitoring (quarterly CCM reports, VDR
  timeframes, SCN), and what it requires that nothing here automates
- **`CHANGELOG.md`**: change history, in the spirit of the documentation
  discipline FedRAMP's Significant Change Notification (SCN) rules expect

## FIPS endpoints

Every root configuration in this repo (`moderate/`, `high/`, `examples/`) sets
`use_fips_endpoint = var.use_fips_endpoint` on the AWS provider, defaulting to
`true`, so all Terraform API calls go to FIPS 140 validated endpoints. Under
FedRAMP's `CMU-CSO-UVM`, validated crypto is a MUST for Class D and a SHOULD for
Class C.

- **Calling the modules from your own root?** Modules don't configure
  providers, so set `use_fips_endpoint = true` in your own `provider "aws"`
  block (or export `AWS_USE_FIPS_ENDPOINT=true`).
- **Coverage checked:** every service these modules call resolves to a FIPS
  endpoint in us-east-1, us-west-2, us-gov-west-1 and us-gov-east-1. This was
  checked against the AWS SDK's endpoint rules and DNS, including S3 and S3
  Control. In GovCloud, the FIPS endpoints for many services are the standard
  regional hostnames ([AWS FIPS endpoints](https://aws.amazon.com/compliance/fips/)).
- **S3 bucket names must not contain dots.** S3 FIPS endpoints are
  virtual-hosted only. `trail_name` and `config_bucket_name` validate this.
- FIPS endpoints protect the API channel. Data-plane TLS (load balancers,
  databases, your application) is configured separately; see
  `modules/fips-vpc-endpoints` and `docs/COVERAGE-GAPS.md`.

## A Terraform-specific note

Unlike CloudFormation, the Terraform AWS provider has native resources for
a couple of things that required Lambda-backed custom resources in the CFN
version of this library: `aws_iam_account_password_policy` and
`aws_guardduty_organization_configuration` both exist for real. Where
that's true, the module here is simpler and more idiomatic than its CFN
counterpart; where Terraform has the same kind of gap CloudFormation did,
the module says so directly in its README.

## Tests

Every module under `modules/` has a `terraform test` suite in its
`tests/` directory. Each test runs `plan` against the
real AWS provider with dummy credentials, so it needs no AWS account. It
asserts the security properties the control mapping claims, for example:

- the organization trail is multi-region with log file validation on
- every CloudTrail grant on the log bucket is pinned to the trail's ARN
- the SCP denies stopping CloudTrail, Config, GuardDuty and Security Hub
- ARNs use the GovCloud partition when deployed there
- invalid inputs (dotted bucket names, malformed org IDs) are rejected

```sh
cd modules/org-cloudtrail
terraform init -backend=false
terraform test
```

## Security scanning

Every push and PR to `main` runs automatically via GitHub Actions
(`.github/workflows/ci.yml`, `security-scan.yml` and `codeql.yml`):

- **Module README tables**: `terraform-docs` fails the build if a module README is stale
- **`terraform fmt` + tflint**: formatting and Terraform best practices
- **`terraform test`**: plan-only tests for the modules listed under
  [Tests](#tests)
- **Lambda tests**: pytest and ruff for the module Lambdas, plus a
  PostgreSQL 16 run of the SQL role audit
- **Gitleaks, Checkov, Trivy and zizmor** (`security-scan.yml`, a shared
  workflow): secret scanning and independent security/compliance scanners
  against the templates themselves
- **CodeQL** (`codeql.yml`): static analysis of the Lambda Python

Check the **Actions** tab on GitHub after your first push; new modules
sometimes get flagged for things that are intentional design choices in a
security baseline (for example, the permission boundary in
`modules/iam-access-control` allows `s3:*` and three other whole services
on this account's resources as a ceiling, then denies the dangerous
actions; that is deliberate, not an oversight). Where a finding is an accepted
risk rather than a bug, add a `#checkov:skip=CKV_AWS_XXX:<reason>` comment
directly above the resource so the justification travels with the code;
see `CONTRIBUTING.md` for the pattern.

## Getting started

1. Start with `modules/`: these are the foundational building blocks
   (organization CloudTrail, AWS Config, GuardDuty, Security Hub, IAM
   password policy) that nearly every control family in Moderate, High, and
   every KSI category in 20x depends on. Each module is self-contained
   with its own `variables.tf`, `main.tf`, `outputs.tf`, and `README.md`.
2. Reference the modules you need from your own root Terraform
   configuration:
   ```hcl
   module "org_cloudtrail" {
     source          = "github.com/DustyStudy/fedramp-terraform-library//modules/org-cloudtrail?ref=v4.1.0"
     organization_id = "o-xxxxxxxxxx"
   }
   ```
   Pin module sources to a reviewed release tag (or full commit SHA) and upgrade
   explicitly after reviewing the changelog and Terraform plan. The provider lock
   file does not pin Git module sources. `SECURITY.md` says which release
   line gets fixes and how to [verify a release](SECURITY.md#verifying-a-release)
   (`gh release verify`, and for releases after v3.0.0 `sha256sum -c` and
   `gh attestation verify`).

3. Check `docs/control-mapping.md` to see which NIST 800-53 control IDs (or
   KSI IDs) each module addresses, and use it to build your control
   implementation evidence for your SSP.

## Contributing

See `CONTRIBUTING.md`. PRs that add control mapping documentation alongside
new modules are especially welcome.

## Reporting a security issue

See `SECURITY.md`; please don't open a public issue for a security
finding.

## License

MIT, see `LICENSE`. Releases up to and including v1.0.0 were published
under Apache License 2.0.
