# Contributing

Thanks for considering a contribution. This repo is meant to be a practical,
trustworthy reference — please keep a few things in mind.

## Ground rules

- **Map every module to its control(s) or KSI(s).** A module without a
  mapping in `docs/control-mapping.md` isn't useful to someone building an
  SSP. State the NIST 800-53 Rev5 control ID (e.g. `AC-2`, `AU-6`) or the
  FedRAMP 20x KSI ID (e.g. `KSI-MLA-01`) in a comment block at the top of
  `main.tf` and in the docs table.
- **No hardcoded account IDs, ARNs, or secrets.** Use variables, data
  sources, or Secrets Manager references.
- **Least privilege by default.** IAM policies should scope to specific
  resources/actions, not `*:*`. If a wildcard is genuinely required (e.g.
  an account-level API with no ARN to scope to), explain why in a comment.
- **Prefer native Terraform resources over `local-exec`/custom scripts**
  wherever the provider supports it. If a control genuinely has no native
  resource (rare, but it happens — check the AWS provider docs before
  assuming), a `null_resource` with `local-exec`, or documenting the manual
  step, are the fallback options; explain the gap in the module's README.
- **Run `terraform fmt` before committing.** CI checks formatting and will
  fail an unformatted PR.
- **Test before submitting a PR.** Run `terraform init && terraform plan`
  in a sandbox account and confirm the plan matches intent.
- **Note any assumptions** (e.g. "assumes AWS Organizations is already set
  up", "assumes a delegated administrator account for security services").

## PR checklist

- [ ] `terraform fmt -check` passes
- [ ] `terraform validate` passes
- [ ] tflint and Checkov pass in CI (or findings are explicitly skipped
      with justification — see below)
- [ ] Control/KSI mapping added to `docs/control-mapping.md`
- [ ] No hardcoded account IDs, ARNs, or credentials
- [ ] Module README updated if this changes scope
- [ ] Planned/applied successfully in a test account

## Handling a Checkov finding you disagree with

Security baseline modules sometimes need patterns Checkov flags by
default — a deliberately broad IAM policy for an account-level API, a
wildcard resource where the action doesn't support ARN scoping, etc.
Don't silence these by disabling the whole check repo-wide. Instead, skip
it at the specific resource with a reason, so the next reader (including
future-you) can see why:

```hcl
resource "aws_iam_role_policy" "example" {
  #checkov:skip=CKV_AWS_XXX:Why this is intentional, not an oversight
  ...
}
```

If you're not sure whether a finding is a real issue or an accepted
trade-off, open the PR anyway and flag it in the description — that's a
useful discussion to have in the open.
