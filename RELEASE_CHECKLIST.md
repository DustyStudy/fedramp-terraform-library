# Release checklist: v4.1.0

Release branch: `release/4.1.0` (cut from `main` at `391e3a6`).
Scope: the `[Unreleased]` CHANGELOG entries, PRs #91 to #95, merged after v4.0.0.
Process: `CONTRIBUTING.md` > Releasing (release PR, then a maintainer tags
`v4.1.0` on `main`; `release.yml` publishes). Tagging, merging to `main` and
publishing need the owner's approval.

Supported environments (from `versions.tf` and `ci.yml`): Terraform `>= 1.12`
(CI floor 1.12.0, latest 1.17.2), AWS provider `>= 6.0, < 7.0`, archive
provider `>= 2.4`, Lambda Python 3.12, commercial and GovCloud partitions.

Status: PASS, FAIL, OPEN (not yet run), BLOCKED (needs the owner or an
external change), N/A.

| # | Criterion | Status | Evidence / blocker |
|---|-----------|--------|--------------------|
| 1 | `terraform fmt -check -recursive` passes | PASS | Local, 2026-11-24, `main@391e3a6` |
| 2 | TFLint (`--minimum-failure-severity=warning`) passes | PASS | CI run 45475984217 on `main@391e3a6` (not run locally: tflint blocked by local permissions) |
| 3 | Module README tables match terraform-docs | PASS | CI run 45475984217 |
| 4 | Every module and root validates; `terraform test` passes at floor and latest versions | PASS | CI run 45475984217 (both legs). Local TF 1.16.6: burst detector 10/10, account-baseline 23/23, logging-monitoring 10/10, org-scp-boundary 17/17; `moderate/logging-monitoring` validates |
| 5 | Committed root lock files complete | PASS | CI run 45475984217 |
| 6 | Lambda unit tests and ruff pass | PASS | Local pytest 432 passed (mocked boto3); CI run 45475984217 |
| 7 | SQL role audit passes on PostgreSQL 16 | PASS | CI run 45475984217 |
| 8 | Security Scan (gitleaks, Checkov, Trivy, zizmor) and CodeQL pass; no open code-scanning, Dependabot or secret-scanning alerts | PASS | Runs 45475985160, 45475984276; alert APIs returned 0 open, 2026-11-24 |
| 9a | Vault Lock / deny-delete vault policy (`account-baseline`) | PASS (local) | Blocker fixed: protecting the vault now requires an exempt principal and `create_backup_vault`; condition always rendered; all 7 actions, Principal and exemptions asserted; AWS 36,500-day bounds; IAM-ARN check. `terraform test` 27/27 |
| 9b | Identity Center MFA alarm (`logging-monitoring`) | PASS (local) | **Blocker fixed:** `$.readOnly=false` never matched a JSON boolean; now `IS FALSE`. Lead's own `TestMetricFilter` (us-east-1, read-only, synthetic events): old pattern 0/4, new pattern matches exactly the 2 MFA/passkey writes. Secret-read filter: adds `GetParameterHistory` (verified match), expected-reader wildcard excludes `app/*` but not `app2`; 1,024-char precondition; IAM role ARNs rejected. `terraform test` 12/12 |
| 9c | MFA-removal SCP (`org-scp-boundary`) | PASS (local) | Was: indented SCP with 4 SSO-style exempt ARNs + IMDSv2 in GovCloud = 5,156-5,272 chars > 5,120 (apply fails). Now submitted minified (`jsonencode(jsondecode(...))`; 6 ARNs = 4,325) with a plan-time `<= 5120` precondition; provider suppresses equivalent-policy diffs, so no perpetual diff. `ResyncMFADevice` removed from the deny. `terraform test` 19/19 |
| 9d | `secret-access-burst-detector` | FAIL (fixing) | No blockers. Default 30-min window with 15-min schedule reliably correlates only ~10 min; `GetParameterHistory` missing; `StartQuery` limit unset; input validation gaps |
| 10 | Docs consistent: module inventory, control mapping, NIST matrix, module READMEs, links | PASS (pending CI) | Fixed 23→24 counts, catalog rows, CP-9/CP-10/IA-2 matrix rows, CRM, org-governance Vault Lock pointer, control-mapping IA/CP-10, `?ref=v4.1.0` pins, output descriptions. Links clean. Test-count text updated after the final run |
| 11 | Release PR: CHANGELOG `[4.1.0]` section, README `?ref=v4.1.0`, README test summary | OPEN | |
| 12 | Full CI green on the release PR head | OPEN | |
| 13 | Live plan/apply of changed modules in a sandbox account (CONTRIBUTING PR checklist) | BLOCKED | Needs owner-provided sandbox account and approval; all module tests are plan-only with mocked providers |
| 14 | Tag `v4.1.0` and `release.yml` publishes attested assets | BLOCKED | Needs owner approval to merge to `main` and tag |

## Decisions

- Version 4.1.0 (minor): every Unreleased change is additive and off by
  default, except `org-scp-boundary`'s new `DenyMfaRemovalWithoutMfa`
  statement, which is on for everyone who applies the module (see criterion 9).
- `account-baseline`: the vault deny policy now requires at least one exempt
  principal, rejected at plan time. A policy no one can change is worse than
  compliance-mode Vault Lock, which at least has a grace period.
- Not done: the `moderate/` and `high/` `account-baseline` roots do not expose
  the new backup inputs (they never exposed `create_backup_vault` either).
  Callers who want immutability call the module directly. Deferred; this is a
  feature, not a release blocker.

## AWS resources created for this run

None.

## Next step

Integrate review findings on `release/4.1.0`, then open the release PR.
