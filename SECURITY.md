# Security Policy

## What "security" means for this repo

This is a library of Terraform modules, not a running service — there's
no production deployment to compromise. "Security issue" here means a
module doing something other than what it claims to: a resource that
ships with a weaker default than its README states, an IAM or key policy
that's more permissive than intended, a control that silently doesn't
apply in some configuration, or two modules whose resources conflict when
used together (see `examples/README.md` for two of these found and fixed
already).

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a security finding —
that publishes the gap before there's a fix.

Instead, use GitHub's private reporting for this repo: go to the
**Security** tab → **Report a vulnerability**, which opens a private
advisory only visible to the maintainer until it's resolved. Include:

- The module and resource(s) affected
- What the current behavior is vs. what it should be
- Why it matters (which control it undermines, and how)
- A minimal reproduction (a `terraform plan` diff or the misconfigured
  resource is usually enough — no need to apply anything)

## Response expectations

This is a personally maintained public repo, not a funded security
program — there's no SLA. In practice: acknowledgment within a few days,
and a fix or documented mitigation prioritized ahead of new-module work
once confirmed.

## Supported scope

The latest major release line is supported: currently **3.x**. Security
fixes ship as a new tagged release on that line (a patch release such as
`v3.0.1` where the fix is not a breaking change) and are recorded in
`CHANGELOG.md`. Earlier majors (1.x, 2.x) get no fixes; upgrade using the
changelog's upgrade notes. `main` is the development branch and can be
ahead of the latest release, so pin a release tag or a full commit SHA in
your `source` reference, not `main`.

## Verifying a release

Releases in this repository are immutable: once published, GitHub does not
let the tag be moved or the assets be changed, and it signs a release
attestation recording which commit the tag points to. Check it with the
GitHub CLI:

```sh
gh release verify v3.0.0 --repo DustyStudy/fedramp-terraform-library
```

The command prints the commit the tag resolves to. A Git module source
(`?ref=v3.0.0`) is not checked by Terraform against anything, so for the
strongest pin use that full commit SHA as the `ref`.

Releases **after v3.0.0** are published by
`.github/workflows/release.yml` and also carry a source tarball, a
`SHA256SUMS` file, an SPDX SBOM (`sbom.spdx.json`) and a build provenance
attestation. v3.0.0 and earlier have no assets. To verify a download
(replace `X.Y.Z`):

```sh
gh release download vX.Y.Z --repo DustyStudy/fedramp-terraform-library
sha256sum -c SHA256SUMS
gh attestation verify fedramp-terraform-library-X.Y.Z.tar.gz \
  --repo DustyStudy/fedramp-terraform-library \
  --signer-workflow DustyStudy/fedramp-terraform-library/.github/workflows/release.yml
```

`sha256sum -c` only shows the files match the checksum file that came with
them. `gh attestation verify` is the check that ties the tarball to this
repository's release workflow and the tagged commit. The SBOM lists what
the scanner finds in the tree (GitHub Actions and the Python development
requirements). The modules set provider version ranges, not locked
versions, so commit your own `.terraform.lock.hcl` to pin providers.

Tags are not GPG- or SSH-signed. The release attestation above is the
evidence that a tag has not moved.

## Not in scope

- Findings from Checkov/Trivy that are already tracked as accepted risk
  with a `#checkov:skip=...:<reason>` comment in the code (see
  `CONTRIBUTING.md`) — these are deliberate, documented trade-offs, not
  vulnerabilities.
- Gaps explicitly listed in `docs/COVERAGE-GAPS.md` (personnel security,
  training, the SSP itself, tested IR/contingency plans, and other
  process controls this repo was never meant to automate).
- General FedRAMP authorization questions — see the disclaimer in the
  root `README.md`. This repo supports control implementation; it isn't
  itself an ATO.
