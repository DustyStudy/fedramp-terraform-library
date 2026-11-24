# proof/: live-test fixtures, not reference code

**Do not copy these stacks into production, and do not use them as a
starting point.** For a reference composition use
[`examples/`](../examples), and for the per-track roots use
[`moderate/`](../moderate) and [`high/`](../high).

These stacks exist to deploy the library's modules into sandbox accounts
for a few hours, run probes against the real APIs, and be destroyed. The
results are written up in [`docs/LIVE-PROOF.md`](../docs/LIVE-PROOF.md) and
the raw probe output is in [`docs/proof/`](../docs/proof).

## Why they are unsafe to reuse

- **Deliberately weak resources.** `member/` creates resources for the
  auditor modules to find: a PostgreSQL instance that is single-AZ, uses
  a password instead of IAM authentication, does not enforce TLS and
  skips its final snapshot; a role that trusts another account with no
  external ID; and a role with an OIDC trust that pins no audience or
  subject.
- **Scanner findings are skipped, not fixed.** The stacks carry more than
  two dozen `checkov:skip` comments, with reasons such as "Fixture. Lives for one
  proof run."
- **Sized and wired for a short run:** small instance classes, no
  backend (local state), and a fixture database with no deletion
  protection.
- **Not covered by CI validation.** `ci.yml` validates and tests
  `modules/`, `moderate/`, `high/` and `examples/`. It does not run
  `terraform validate` on `proof/`.

## What is here

| Path | Purpose |
|---|---|
| `member/` | Account-scoped modules with their defaults in one sandbox member account, plus the weak fixtures above. `probe.py` and `dataplane_probe.py` check them. |
| `management/` | The two auditors that need the organization management account. |
| `member-role/` | The read-only role the stale-account detector assumes, for one member account. |
| `access-control/` | `iam-access-control`. |
| `cloudtrail-key/` | One statement of the `org-cloudtrail` key policy, applied with `-target`. |
| `eks-config/` | `eks-hardened` and `config-conformance-pack`, with `network-perimeter-vpc`. |
| `patching/` | `ssm-patching-hardened` and `moderate/network-boundary/vpc-flow-logs`. |
| `release-4.1.0/` | v4.1.0 checks: `burst/` (`secret-access-burst-detector` with its own trail) and `backup/` (`account-baseline` vault lock and deny policy, applied with `-target`). Its `probe.py` runs them. |
| `controls_probe.py` | Probe for the patching, CloudTrail-key and access-control stacks. |

Applying any of these creates billable resources and, in `member/`,
knowingly non-compliant ones. If you rerun the proof, use a sandbox
account, follow the teardown steps in
[`docs/LIVE-PROOF.md`](../docs/LIVE-PROOF.md), and destroy the stack the
same day.
