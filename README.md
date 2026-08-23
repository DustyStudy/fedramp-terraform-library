# FedRAMP Terraform Library

Reusable Terraform modules that implement common controls and security
patterns for organizations pursuing **FedRAMP Moderate**, **FedRAMP
High**, or **FedRAMP 20x** authorization. This is the Terraform
counterpart to [fedramp-cfn-library](https://github.com/DustyStudy/fedramp-cfn-library)
— same scope, same disclaimer, same track structure, different tool.

## ⚠️ Disclaimer

These modules support the *implementation* of security controls. They do
**not**, by themselves, constitute a FedRAMP authorization. An Authority to
Operate (ATO) requires an agency sponsor, a 3PAO (Third Party Assessment
Organization) assessment, and an approved System Security Plan (SSP). Treat
this repo as a starting point for your control implementation evidence — not
a substitute for the assessment process.

Modules are provided as-is with no warranty. Review every variable,
resource, and IAM policy before applying to any environment, and validate
against your organization's current SSP and your 3PAO's expectations.

## Why three separate tracks?

- **`moderate/`** and **`high/`** map to the NIST SP 800-53 Rev5 control
  baselines. High reuses Moderate's modules with tighter variable values
  (longer log retention, stricter crypto, broader MFA enforcement) via
  `.tfvars` overrides rather than duplicating module code.
- **`fedramp-20x/`** is *not* a control baseline. FedRAMP 20x
  authorizations are validated against machine-readable **Key Security
  Indicators (KSIs)** — a fundamentally different assessment model that is
  still being piloted. See `fedramp-20x/README.md` for current status and
  a cross-reference of which existing modules already satisfy each KSI
  category.

## Structure

```
modules/              Shared baseline modules used across all three tracks
moderate/             Rev5 Moderate baseline, by control family
high/                 Rev5 High — reuses moderate/ with tfvars overrides
fedramp-20x/          KSI-based cross-reference (CNA, IAM, MLA, CNBC, SVC, INR)
docs/                 Control-to-module cross-reference
```

## Modules

| Module | What it does |
|---|---|
| `org-cloudtrail` | Organization-wide CloudTrail, KMS-encrypted, with a dedicated access-log bucket |
| `config-conformance-pack` | AWS Config recorder + delivery channel + FedRAMP Moderate conformance pack |
| `guardduty-org` | GuardDuty with organization auto-enrollment, findings routed to SNS |
| `security-hub-org` | Security Hub with default standards + organization auto-enrollment |
| `iam-password-policy` | Account-wide IAM password policy |
| `account-baseline` | EBS default encryption, S3 account public access block, optional default-VPC/SG lockdown |
| `ecr-hardened` | KMS-encrypted ECR repository, tag immutability, scan-on-push |
| `ecs-fargate-hardened` | ECS cluster with Container Insights and KMS-encrypted logging (incl. ECS Exec) |
| `eks-hardened` | EKS cluster with KMS secrets envelope encryption, full control-plane logging, private-only endpoint |
| `fips-vpc-endpoints` | VPC interface endpoints — see the module's `variables.tf` for which services genuinely have FIPS-suffixed endpoints and which don't |
| `network-perimeter-vpc` | 3-tier VPC with KMS-encrypted Flow Logs and a locked-down default security group |
| `org-governance` | Workload-perimeter SCP, AI-services opt-out policy, centralized backup policy |
| `org-scp-boundary` | Region-lock SCP, security-service protection, insecure-transport deny |
| `rds-postgres-hardened` | Multi-AZ PostgreSQL with enforced TLS, KMS encryption, managed master password |
| `ssm-patching-hardened` | Automated patch baseline, weekly maintenance window, KMS-encrypted patch logs |
| `waf-hardened` | Regional WAFv2 with AWS-managed rule groups, rate limiting, KMS-encrypted logging |
| `moderate/iam-access-control` | Access Analyzer, permission boundary, enforced-MFA group, root usage alerting |
| `moderate/logging-monitoring` | 14 CIS/Security Hub CloudWatch metric-filter + alarm pairs |
| `moderate/incident-response` | Aggregated SNS topic for high-severity GuardDuty/Security Hub findings |

See `docs/control-mapping.md` for the NIST 800-53/20x KSI mapping per
module, and `docs/NIST-800-53-REV5-MATRIX.md` for the same information
organized by control ID instead.

## Compliance documentation beyond control mapping

Passing a FedRAMP audit takes more than deployed infrastructure. These
docs are aimed at that gap directly:

- **`docs/CUSTOMER-RESPONSIBILITY-MATRIX.md`** — what AWS already covers,
  what this repo automates, what's still a manual process
- **`docs/COVERAGE-GAPS.md`** — control families and requirements this
  repo genuinely cannot address (personnel security, training, the SSP
  itself, tested IR/contingency plans, and more), stated plainly rather
  than left implicit
- **`docs/CONTINUOUS-MONITORING.md`** — how this repo's modules feed
  FedRAMP's monthly/annual ConMon deliverables, and what ConMon requires
  that nothing here automates
- **`docs/POAM-TEMPLATE.md`** — a starting point for tracking findings;
  get FedRAMP's official POA&M workbook for actual submissions
- **`CHANGELOG.md`** — change history, in the spirit of the documentation
  discipline FedRAMP's Significant Change Request process expects

## A Terraform-specific note

Unlike CloudFormation, the Terraform AWS provider has native resources for
a couple of things that required Lambda-backed custom resources in the CFN
version of this library — `aws_iam_account_password_policy` and
`aws_guardduty_organization_configuration` both exist for real. Where
that's true, the module here is simpler and more idiomatic than its CFN
counterpart; where Terraform has the same kind of gap CloudFormation did,
the module says so directly in its README.

## Security scanning

Every push and PR to `main` runs automatically via GitHub Actions
(`.github/workflows/ci.yml`), in three jobs:

- **Gitleaks** — secret/credential scanning
- **`terraform fmt` + tflint** — formatting and Terraform best practices
- **Checkov** (blocking) and **Trivy** (reporting to the Security tab) —
  two independent security/compliance scanners against the templates
  themselves

Check the **Actions** tab on GitHub after your first push — new modules
sometimes get flagged for things that are intentional design choices in a
security baseline (for example, the permission boundary's broad `NotAction`
grant is deliberate, not an oversight). Where a finding is an accepted
risk rather than a bug, add a `#checkov:skip=CKV_AWS_XXX:<reason>` comment
directly above the resource so the justification travels with the code —
see `CONTRIBUTING.md` for the pattern.

## Getting started

1. Start with `modules/` — these are the foundational building blocks
   (organization CloudTrail, AWS Config, GuardDuty, Security Hub, IAM
   password policy) that nearly every control family in Moderate, High, and
   every KSI category in 20x depends on. Each module is self-contained
   with its own `variables.tf`, `main.tf`, `outputs.tf`, and `README.md`.
2. Reference the modules you need from your own root Terraform
   configuration:
   ```hcl
   module "org_cloudtrail" {
     source          = "github.com/DustyStudy/fedramp-terraform-library//modules/org-cloudtrail"
     organization_id = "o-xxxxxxxxxx"
   }
   ```
3. Check `docs/control-mapping.md` to see which NIST 800-53 control IDs (or
   KSI IDs) each module addresses, and use it to build your control
   implementation evidence for your SSP.

## Contributing

See `CONTRIBUTING.md`. PRs that add control mapping documentation alongside
new modules are especially welcome.

## License

Apache License 2.0 — see `LICENSE`.
