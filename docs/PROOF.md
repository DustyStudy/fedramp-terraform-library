# What is verified, and what is not

This page covers the plan-time evidence: every check below runs offline,
against the resources and policy JSON that Terraform renders, with dummy
credentials in the test files. It lists what those checks cover, the
numbers from the last run, and the gaps. Fifteen modules have also been
deployed to a real organization and probed with real API calls; that run
is in [LIVE-PROOF.md](LIVE-PROOF.md).

Numbers are from 2026-10-10 at commit `57a1db4`. The `terraform test`,
pytest and Checkov counts come from that commit's CI run (Terraform
1.14.6); the `terraform validate` and provider allowlist rows are from a
local run (Terraform 1.16.4). CI runs the same checks on every pull
request.

## Summary

| Check | Result |
|---|---|
| `terraform test` (23 of 23 modules, the High account baseline and the Moderate flow-log stack, local run of 2026-11-13 on Terraform 1.16.6) | 138 runs, 138 passed |
| pytest (module Lambdas, local run of 2026-11-13) | 288 passed |
| Provider allowlist guard (`tests/python/test_provider_sources.py`, added 2026-09-30) | 45 `required_providers` declarations checked, all allowlisted; 4 guard self-tests passed |
| `terraform validate` | 23 of 23 modules and 14 of 14 roots under `moderate/`, `high/` and `examples/` valid |
| Checkov (`--framework terraform`, CI run of 2026-10-10 at `57a1db4`) | 992 passed, 0 failed, 235 skipped |
| Trivy config scan, Gitleaks, `terraform fmt`, TFLint | Run in CI on every PR |

Every Checkov skip is an inline `checkov:skip=<ID>: <reason>` comment next
to the resource, so each exception is reviewable in the code. The most
common are `CKV_AWS_356` (23), `CKV_AWS_109` and `CKV_AWS_111` (20 each),
mostly on KMS key policies, which must grant the account root `kms:*` on
`*`.

## What the `terraform test` suites assert

Each run plans the module with fixed inputs and asserts on the planned
resources. Several runs also feed in invalid input and expect the
variable validation to reject it.

| Module | Runs | What the runs assert |
|---|---:|---|
| `account-baseline` | 5 | Account-level guardrails are on; password policy follows NIST SP 800-63B-4; the default security group denies all traffic; the backup vault gets a dedicated rotating CMK, or uses a supplied key |
| `config-conformance-pack` | 6 | The recorder is created and switched on; AWS Config can write to its bucket; delivery is encrypted with a rotating CMK; no pack is created without a template; a pack can come from S3; supplying both template sources is rejected |
| `guardduty-org` | 5 | The detector enables all classic protections; new accounts are enrolled; findings alert at Medium or higher; `auto_enable = false` means `NONE`; an unknown publishing frequency is rejected |
| `iam-password-policy` | 3 | Defaults follow NIST SP 800-63B-4; composition rules are opt-in; a minimum length below the NIST floor is rejected |
| `identity-center-access-auditor` | 5 | The Lambda role is read-only; settings reach the Lambda; it runs daily with encrypted logs; the topic uses the module CMK |
| `trust-policy-auditor` | 6 | It can't assume any role unless `member_role_name` is set, and then only that role; the Lambda role and the member-account policy are read-only; settings reach the Lambda; it runs daily with encrypted logs and a CMK-encrypted topic; a role ARN or a malformed account ID is rejected |
| `rds-access-auditor` | 6 | It can't list the organization or assume any role unless `member_role_name` is set, and then only that role; the Lambda role and the member-account policy are read-only; settings reach the Lambda; it runs daily with encrypted logs and a CMK-encrypted topic; a role ARN or a malformed region is rejected |
| `org-cloudtrail` | 7 | The trail covers the whole organization; logs use a rotating CMK; buckets block public access and are versioned; the bucket policy blocks confused-deputy access and plain HTTP; ARNs use the current partition; dotted trail names and malformed organization IDs are rejected |
| `org-scp-boundary` | 6 | The SCP denies disabling security services; the region lock uses the approved regions; insecure transport is denied; the policy attaches to every target; the IMDSv2 rule is off by default and, when on, denies both launch without IMDSv2 and downgrade |
| `security-hub-org` | 2 | Default standards and organization enrollment are on; standards auto-enable can be turned off |
| `stale-account-detector` | 7 | The Lambda role and the member policy are read-only; it can't assume any role unless `member_role_name` is set, and then only that role; settings reach the Lambda; a window over 90 days or a role ARN is rejected; the Lambda is encrypted and has a DLQ; the topic uses the module CMK |
| `ecr-hardened` | 4 | Tags are immutable, images are scanned on push and encrypted with a rotating CMK whose policy uses the current partition; the lifecycle policy has one prefix per rule and unique priorities |
| `ecs-fargate-hardened` | 4 | Container Insights is on; ECS Exec sessions log to an encrypted group kept 365 days; only CloudWatch Logs in this account and region may use the CMK |
| `eks-hardened` | 5 | The API endpoint is private only; all five control-plane log types are on; secrets are envelope-encrypted with a rotating CMK scoped to the cluster's log group; the cluster role is EKS-only and its policy ARN uses the current partition |
| `fips-vpc-endpoints` | 3 | KMS, EC2 and STS use their `-fips` endpoint services; interface endpoints use private DNS; S3 uses a gateway endpoint; the security group allows only TLS from the VPC and no egress |
| `incident-notifications` | 4 | The topic CMK rotates and only EventBridge in this account may use it; GuardDuty severity 7+ and new Security Hub CRITICAL/HIGH findings are routed; an out-of-range threshold is rejected |
| `logging-monitoring` | 5 | All 14 CIS alarms watch the metric their own filter publishes and fire on a single event; the root and CMK filters match the right events; the topic CMK rotates and is limited to this account |
| `network-perimeter-vpc` | 5 | Flow logs capture all traffic at one-minute intervals for 365 days; the default security group has no rules; no subnet assigns public IPs; the flow-log role trust is limited to this account's flow logs |
| `org-governance` | 7 | Every SCP statement denies root use, internet gateways, IAM users and Object Lock changes by anyone but the named admins; policy types and attachments are right; AI services are opted out with no child override; the backup policy uses the given regions, retention and partition, adds a copy only when asked, and rejects retention under 120 days; with no admins the Object Lock deny has no condition, and several admins are all exempt |
| `rds-postgres-hardened` | 5 | The instance is private, encrypted, Multi-AZ and deletion-protected, uses Secrets Manager and IAM auth; TLS is required and connections and DDL are logged; the security group allows only PostgreSQL from the VPC; the monitoring role trusts only this database |
| `waf-hardened` | 3 | The three AWS managed rule groups run without count overrides; the per-IP rate rule blocks at `rate_limit_threshold`; request sampling is off; logs redact the Authorization and Cookie headers and go to an `aws-waf-logs-` group kept 365 days |

The pytest suites (`tests/python/`) run the Lambda handlers for
`identity-center-access-auditor`, `rds-access-auditor`,
`stale-account-detector` and `trust-policy-auditor` against mocked boto3
clients. CI also runs `rds-access-auditor`'s SQL role audit against
PostgreSQL 16 with a fixture role per finding (`tests/sql/`).

## Reproduce it

```bash
# Module tests (no AWS credentials needed)
for dir in $(find . -path '*/tests/*.tftest.hcl' -not -path '*/.terraform/*' \
    -exec dirname {} \; | xargs -n1 dirname | sort -u); do
  terraform -chdir="$dir" init -backend=false -input=false >/dev/null
  terraform -chdir="$dir" test
done

# Lambda tests
pip install pytest boto3
python -m pytest tests/python -q

# Validate every module
for dir in modules/*; do
  terraform -chdir="$dir" init -backend=false -input=false >/dev/null
  terraform -chdir="$dir" validate
done

# Static analysis
checkov -d . --framework terraform
```

## Gaps

- **Live deployment covers fifteen modules, not the whole repo.** Plan-time
  tests prove what Terraform will request. They do not prove what AWS
  accepts or how the policies behave at request time.
  [LIVE-PROOF.md](LIVE-PROOF.md) lists which modules were deployed and
  which were not. For SCP and permissions-boundary behavior tested with
  real API calls, see the live proof in
  [aws-org-guardrails](https://github.com/DustyStudy/aws-org-guardrails/blob/main/docs/PROOF.md).
- **Plan-time tests cannot see every value known only after apply.** Most
  suites override the ARNs AWS assigns at create time to prove each
  resource uses its module's CMK, topic or role. The
  `incident-notifications` topic policy's `aws:SourceArn` scoping still
  renders unknown at plan time, so no suite asserts on it.
- **`fedramp-20x/` holds no Terraform.** It maps each KSI cluster to the
  modules above. Whether a module's evidence satisfies a KSI's validation
  method is a judgment for your assessor.
- **Controls that code cannot implement** (policies, training, IR
  exercises, contingency testing) are listed in
  [COVERAGE-GAPS.md](COVERAGE-GAPS.md).
