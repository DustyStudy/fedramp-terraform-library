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

## A Terraform-specific note

Unlike CloudFormation, the Terraform AWS provider has native resources for
a couple of things that required Lambda-backed custom resources in the CFN
version of this library — `aws_iam_account_password_policy` and
`aws_guardduty_organization_configuration` both exist for real. Where
that's true, the module here is simpler and more idiomatic than its CFN
counterpart; where Terraform has the same kind of gap CloudFormation did,
the module says so directly in its README.

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
