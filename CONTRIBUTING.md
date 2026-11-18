# Contributing

Thanks for considering a contribution. This repo is meant to be a practical,
trustworthy reference — please keep a few things in mind.

## Ground rules

- **Map every module to its control(s) or KSI(s).** A module without a
  mapping in `docs/control-mapping.md` isn't useful to someone building an
  SSP. State the NIST 800-53 Rev5 control ID (e.g. `AC-2`, `AU-6`) or the
  FedRAMP 20x KSI ID (e.g. `KSI-MLA-OSM`) in a comment block at the top of
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
- **Only allowlisted providers.** A new `required_providers` entry must
  be added to `ALLOWED_PROVIDERS` in `tests/python/test_provider_sources.py`
  in the same PR, or CI fails. Copy the namespace from the provider's
  registry page rather than typing it: the 2026-09 Graphalgo campaign
  shipped malware as `kreuzwenker/docker`, one letter off
  `kreuzwerker/docker`. Prefer HashiCorp or verified-partner providers,
  and say in the PR why the new one is trusted (SR-3, SR-11).
- **Run `terraform fmt` before committing.** CI checks formatting and will
  fail an unformatted PR.
- **Test before submitting a PR.** Run `terraform init && terraform plan`
  in a sandbox account and confirm the plan matches intent.
- **Note any assumptions** (e.g. "assumes AWS Organizations is already set
  up", "assumes a delegated administrator account for security services").

## Running the checks locally

There is no pre-commit configuration; CI is the gate. To catch failures
before pushing, run the same commands CI does, from the repository root:

```sh
terraform fmt -check -recursive
tflint --init && tflint --recursive --minimum-failure-severity=warning
for d in modules/*/; do terraform-docs "$d"; done   # then commit any README changes
pip install --require-hashes -r requirements-dev.txt
ruff check modules tests
python -m pytest tests/python -q
```

and in each module you changed:

```sh
terraform init -backend=false
terraform validate
terraform test
```

## Review

`.github/CODEOWNERS` names the reviewer for every path. Changes to
`modules/org-scp-boundary`, `modules/org-governance`,
`modules/iam-access-control` and `.github/` get the closest look: a
mistake there reaches every account or the release pipeline.

## PR checklist

- [ ] `terraform fmt -check` passes
- [ ] `terraform validate` passes
- [ ] `terraform test` passes for any module with a `tests/` directory,
      and new security properties get an assertion
- [ ] tflint and Checkov pass in CI (or findings are explicitly skipped
      with justification — see below)
- [ ] Control/KSI mapping added to `docs/control-mapping.md`
- [ ] No hardcoded account IDs, ARNs, or credentials
- [ ] Any new provider is allowlisted in `tests/python/test_provider_sources.py`
- [ ] Module README updated if this changes scope
- [ ] Planned/applied successfully in a test account

## Releasing (maintainers)

1. Merge a PR that moves the `[Unreleased]` entries in `CHANGELOG.md`
   under a new `## [X.Y.Z] - YYYY-MM-DD` heading and updates the
   `?ref=` example in the root `README.md`.
2. Tag that commit on `main` and push the tag:
   `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` builds the source tarball,
   `SHA256SUMS` and SBOM, attests them, and publishes the GitHub release
   with that version's changelog section as the notes.

Do not create the release by hand (`gh release create` or the web UI).
Releases here are immutable, so a release published without assets
cannot have them added, and the workflow fails if the release already
exists. Tags cannot be moved or deleted either: if a release is wrong,
fix forward with a new patch version.

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
