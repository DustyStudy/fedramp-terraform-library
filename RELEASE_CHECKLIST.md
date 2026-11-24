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
| 4 | Every module and root validates; `terraform test` passes at floor and latest versions | PASS (local); CI pending | Local TF 1.16.6 on the integrated tree, 2026-11-24: `terraform validate` 39/39 directories; `terraform test` 253 runs, 253 passed, 28 directories, 0 failed. Floor leg (TF 1.12.0, AWS 6.0.0) only in CI |
| 5 | Committed root lock files complete | PASS | CI run 45475984217 |
| 6 | Lambda unit tests and ruff pass | PASS (local); CI pending | pytest 437 passed (mocked boto3); `ruff check` clean |
| 7 | SQL role audit passes on PostgreSQL 16 | PASS | CI run 45475984217 |
| 8 | Security Scan (gitleaks, Checkov, Trivy, zizmor) and CodeQL pass; no open code-scanning, Dependabot or secret-scanning alerts | PASS | Runs 45475985160, 45475984276; alert APIs returned 0 open, 2026-11-24 |
| 9a | Vault Lock / deny-delete vault policy (`account-baseline`) | PASS (local) | Blocker fixed: protecting the vault now requires an exempt principal and `create_backup_vault`; condition always rendered; all 7 actions, Principal and exemptions asserted; AWS 36,500-day bounds; IAM-ARN check. `terraform test` 27/27 |
| 9b | Identity Center MFA alarm (`logging-monitoring`) | PASS (local) | **Blocker fixed:** `$.readOnly=false` never matched a JSON boolean; now `IS FALSE`. Lead's own `TestMetricFilter` (us-east-1, read-only, synthetic events): old pattern 0/4, new pattern matches exactly the 2 MFA/passkey writes. Secret-read filter: adds `GetParameterHistory` (verified match), expected-reader wildcard excludes `app/*` but not `app2`; 1,024-char precondition; IAM role ARNs rejected. `terraform test` 12/12 |
| 9c | MFA-removal SCP (`org-scp-boundary`) | PASS (local) | Was: indented SCP with 4 SSO-style exempt ARNs + IMDSv2 in GovCloud = 5,156-5,272 chars > 5,120 (apply fails). Now submitted minified (`jsonencode(jsondecode(...))`; 6 ARNs = 4,325) with a plan-time `<= 5120` precondition; provider suppresses equivalent-policy diffs, so no perpetual diff. `ResyncMFADevice` removed from the deny. `terraform test` 19/19 |
| 9d | `secret-access-burst-detector` | PASS (local) | 60-min default window (~40 min reliably correlated); `GetParameterHistory`; `StartQuery` limit; both queries fail closed at the row limit (denied query now filtered to the threshold); `logs:GetQueryResults` scoped to the CloudTrail log group; log-group name and `ignored_principal_arns` validated; epoch-ms timestamps formatted; CMK asserts for Lambda env and DLQ. `terraform test` 12/12. Live Logs Insights behaviour not tested |
| 10 | Docs consistent: module inventory, control mapping, NIST matrix, module READMEs, links | PASS (pending CI) | Fixed 23→24 counts, catalog rows, CP-9/CP-10/IA-2 matrix rows, CRM, org-governance Vault Lock pointer, control-mapping IA/CP-10, `?ref=v4.1.0` pins, output descriptions. Links clean. Test-count text updated after the final run |
| 11 | Release PR: CHANGELOG `[4.1.0]` section, README `?ref=v4.1.0`, README test summary | PASS | `release.yml`'s awk extracts the `[4.1.0]` notes; README and `docs/PROOF.md` counts from the 2026-11-24 run |
| 12 | Full CI green on the release PR head | PASS | PR DustyStudy/fedramp-terraform-library#96 at `67d252d`: pipeline 45488772919 (terraform-docs, fmt + TFLint, module tests floor TF 1.12.0/AWS 6.0.0 and latest TF 1.17.2, lock files, pytest + ruff, SQL audit), Security Scan 45488773606 (Checkov, Gitleaks, Trivy, zizmor), CodeQL 45488772953. CI reruns on this tracker-only commit before merge |
| 13 | Live plan/apply of changed modules in a sandbox account (CONTRIBUTING PR checklist) | PASS except expiry (PENDING) | `proof/release-4.1.0`, account 264524063329, us-east-1, 2026-11-24. Burst detector: runs with scoped `GetQueryResults` and the post-`stats` filter (status 200, no FunctionError) and published a finding for the 8-denied-call + `GetSecretValue` actor. Vault deny policy: `DeleteRecoveryPoint`, `UpdateRecoveryPointLifecycle`, `DeleteBackupVault` all denied by the resource policy for a role IAM allows. Backup expiry under the deny policy: recovery point due 2026-11-25 21:43 UTC; scheduled read-only check `ftl410-backup-expiry-check` at 2026-11-26 12:00 UTC. Details in `docs/LIVE-PROOF.md` |
| 14 | Tag `v4.1.0` and `release.yml` publishes attested assets | PASS | #96 squash-merged as `d13ce7c`; tag `v4.1.0` on `d13ce7c`; release run 45491240056 succeeded; release has `fedramp-terraform-library-4.1.0.tar.gz`, `SHA256SUMS`, `sbom.spdx.json`; `gh release verify v4.1.0` verified attestations for all three |

## Decisions

- Version 4.1.0 (minor): every change is additive. Two take effect on
  upgrade: `org-scp-boundary`'s `DenyMfaRemovalWithoutMfa` statement and the
  two `logging-monitoring` MFA-change alarms; the rest is opt-in. Upgrade
  notes in CHANGELOG cover the SCP.
- `ResyncMFADevice` removed from the MFA-removal deny: resync needs two codes
  from the device, so it cannot strip a factor, and denying it blocks recovery.
- `secret-access-burst-detector`: `logs:GetQueryResults` scoped to the
  CloudTrail log group (AWS lists `log-group*` as its resource type; Codex
  finding, verified in the Service Authorization Reference). Not live-tested;
  the module is off by default and a denial fails the run and its Errors alarm.
- Follow-up, not in this release: `iam-access-control` (main.tf:240-244) also
  grants `logs:GetQueryResults` on `*` with the same incorrect justification.
  It predates 4.1.0; scoping it changes a shipped role.

## Reviews

- Fable reviewers: burst detector, Vault Lock, alarms + SCP. Sonnet: docs.
- Codex (gpt-6-astra, medium, read-only) on `391e3a6..12a76de`: 2 should-fix
  (GetQueryResults wildcard, denied-query truncation) and 1 nit (CHANGELOG
  opt-in claim). All three accepted and fixed; none overruled.
- `account-baseline`: the vault deny policy now requires at least one exempt
  principal, rejected at plan time. A policy no one can change is worse than
  compliance-mode Vault Lock, which at least has a grace period.
- Not done: the `moderate/` and `high/` `account-baseline` roots do not expose
  the new backup inputs (they never exposed `create_backup_vault` either).
  Callers who want immutability call the module directly. Deferred; this is a
  feature, not a release blocker.

## AWS resources created for this run

All in sandbox member account 264524063329, us-east-1, partition `aws`,
created 2026-11-24 ~21:40 UTC as `AWSReservedSSO_AdministratorAccess`. All
are disposable fixtures owned by this run; local state in
`proof/release-4.1.0/{burst,backup}/terraform.tfstate`.

- `proof/release-4.1.0/burst` (32): single-account trail `ftl410-*` to a CWL
  log group, its S3 bucket and KMS key; fixture role `ftl410-burst-actor`;
  secret `ftl410-probe`; capture queue `ftl410-capture`; the
  `secret-access-burst-detector` module (Lambda, KMS key, SNS topic, DLQ,
  EventBridge rule, alarms, log group).
- `proof/release-4.1.0/backup` (11, `-target` only): vault `ftl410-vault`
  with governance-mode Vault Lock (1 day) and the deny vault policy, its KMS
  key, `AWSBackupDefaultServiceRole` (did not exist before), DynamoDB table
  `ftl410-backup-src`, role `ftl410-backup-deleter`; plus one recovery point
  from backup job `7878ae92-2e47-4ed0-bb5f-af7c3ada006c` (1-day lifecycle).
- Not created by this run, left alone: log groups
  `/aws/lambda/ftlproof-db-client`, `/aws/rds/instance/ftlproof-hardened/postgresql`,
  `RDSOSMetrics` from an earlier proof.

Status:
- `burst`: 22 of 32 destroyed 2026-11-24 ~22:40 UTC. `cloudtrail:DeleteTrail`
  is denied by org SCP `p-gww24i22`, so `ftl410-trail` and its log group,
  bucket (with policy and public access block), KMS key and delivery role
  remain until the owner deletes the trail from an exempt principal.
  Tried 2026-11-24: `security-pipeline` (SCP-exempt, assumable from the
  management account) has no `cloudtrail:DeleteTrail` in its IAM policy, and
  SCP `p-ympc9bn9` denies adding one (`iam:PutRolePolicy`). Nothing was
  changed. Removing the trail needs the owner's guardrails pipeline or a
  deliberate SCP change. Ongoing cost: a second copy of management events
  (about $2 per 100,000), CloudWatch Logs ingestion and S3 storage. After the
  trail is gone: `terraform state rm aws_cloudtrail.this` and
  `terraform destroy` in `proof/release-4.1.0/burst`.
- `backup`: up until the expiry check, then destroyed as the exempt admin.

Teardown: `proof/release-4.1.0/README.md`. KMS keys stay pending deletion
7-30 days after destroy.

## Next step

Finish criterion 13 (see `proof/release-4.1.0/README.md`), then tear the
stack down and record the result in `docs/LIVE-PROOF.md`.
