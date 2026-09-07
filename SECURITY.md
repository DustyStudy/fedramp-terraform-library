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

Only the `main` branch is supported. There are no tagged releases yet;
pin to a commit SHA in your own `source` reference if you need
reproducibility, and re-review before moving to a newer commit.

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
