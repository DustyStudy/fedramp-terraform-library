# Live proof

Fifteen of the library's 23 modules have been deployed to a real AWS
Organization and checked with real API calls: thirteen on 2026-10-04 and
2026-10-05, and two more on
[2026-10-10](#later-run-patching-flow-logs-and-access-control). A
[later run](#later-run-data-plane) used four of them: it pushed an image,
sent requests through the web ACL and connected to the database. This page records the
setup, the results, what the run changed in the library, and what it did
not cover. Account IDs are replaced with `111122223333`.

For the plan-time checks that run on every pull request, see
[PROOF.md](PROOF.md).

## Setup

- **Organization:** four active accounts with service control policies
  attached at the root (region restriction, no IAM users, protected
  security services, IMDSv2 required), from
  [aws-org-guardrails](https://github.com/DustyStudy/aws-org-guardrails).
- **Member stack:** [`proof/member`](../proof/member/main.tf), applied to a
  sandbox member account in `us-east-1` as its Identity Center
  administrator, with the provider's `use_fips_endpoint = true`. It calls
  eleven modules with their defaults, sized down only where a default costs
  real money (`db.t3.micro`, 20 GB).
- **Management stack:** [`proof/management`](../proof/management/main.tf),
  applied to the management account in the Identity Center home region. It
  calls the two auditors that need organization-level access.
- **Fixtures:** a role that trusts an OIDC provider with no audience or
  subject condition, a role that trusts another account with no
  `sts:ExternalId`, and a private PostgreSQL instance with a static master
  password, no IAM authentication and TLS optional. None of them grants
  access to anything.
- **Probe:** [`proof/member/probe.py`](../proof/member/probe.py). It reads
  each resource back from AWS, then writes one synthetic CloudTrail event,
  imports one synthetic Security Hub finding, invokes both auditor Lambdas
  and waits for each module's SNS topic to deliver to a capture queue. Its
  raw output is in [`proof/member-run.json`](proof/member-run.json).
- **Versions:** Terraform 1.16.4, AWS provider 6.65.0.

## Results

Terraform created 120 of the 121 planned resources in the member account.
The probe passed 16 of 17 checks.

| Module | Check | Result |
|---|---|---|
| `account-baseline` | Password policy follows NIST SP 800-63B-4 (15 characters, 24 remembered, no expiry) | pass |
| `account-baseline` | EBS encryption is on by default | pass |
| `account-baseline` | S3 account-level public access block is fully on | **not applied** (see below) |
| `account-baseline`, `network-perimeter-vpc` | Default security groups have no rules | pass |
| `account-baseline` | Backup vault uses a rotating customer managed key | pass |
| `network-perimeter-vpc` | Flow log is active, captures all traffic, delivers successfully, and its log group is KMS-encrypted | pass |
| `fips-vpc-endpoints` | All interface endpoints are available, including `kms-fips`, `ec2-fips` and `sts-fips` | pass |
| `ecr-hardened` | Repository is immutable, scans on push and uses a rotating customer managed key | pass |
| `ecs-fargate-hardened` | Cluster logs ECS Exec sessions with KMS and has Container Insights on | pass |
| `waf-hardened` | Web ACL has its four rules and logs with the `authorization` header redacted | pass |
| `rds-postgres-hardened` | Instance is encrypted with a rotating customer managed key, Multi-AZ, private, `rds.force_ssl = 1`, IAM-authenticated, delete-protected, 35-day backups, RDS-managed master secret | pass |
| `logging-monitoring` | A root-usage event in the log group raises `cis-root-account-usage`, and the KMS-encrypted topic delivers the alarm | pass |
| `incident-notifications` | A HIGH Security Hub finding is routed to the KMS-encrypted incident topic | pass |
| `trust-policy-auditor` | The deployed Lambda reports two HIGH findings on the OIDC fixture role | pass |
| `trust-policy-auditor` | Findings are published to the auditor's KMS-encrypted topic | pass |
| `rds-access-auditor` | The deployed Lambda reports `master-credentials`, `transport` and `iam-auth` on the weak fixture, and nothing on the `rds-postgres-hardened` instance | pass |
| `rds-access-auditor` | Findings are published to the auditor's KMS-encrypted topic | pass |

In the management account:

| Module | Check | Result |
|---|---|---|
| `identity-center-access-auditor` | The deployed Lambda audited the organization's real Identity Center instance in 1.7 s and returned one over-privileged permission set and three direct user assignments | pass |
| `stale-account-detector` 2.0 | Deployed on 2026-10-05 with a one-day window. In 3.2 s it read IAM in 2 accounts, listed the 2 accounts that had no member role as errors, and ran both Identity Center checks against real event history. It reported 1 unused console password and 3 unused roles, each of which matched the account's real state, and no unused Identity Center access: all 3 assignments had been used that day. [Result](proof/stale-access-run.json) | pass |

### FIPS endpoints

The member stack's provider ran with `use_fips_endpoint = true`, and all
120 resources were created through it, across EC2, IAM, KMS, Backup,
CloudWatch, CloudWatch Logs, EventBridge, SNS, SQS, Lambda, ECR, ECS,
WAFv2, RDS and Secrets Manager. Both auditor Lambdas ran with
`AWS_USE_FIPS_ENDPOINT=true`.

### Independent scan

[Prowler](https://github.com/prowler-cloud/prowler) 5.43.0 scanned the
sandbox account while the stack was up. On the stack's named resources it
returned 160 results: 134 passed and 26 failed. Nine of the failures are on
the weak fixtures, which exist to fail. The others are listed under
[Follow-ups](#follow-ups).

## What the run changed

Each of these came from the live run and is fixed in the same change that
adds this page.

| Found | Change |
|---|---|
| The management account's Lambda quota in that region is 10 concurrent executions, the floor for new accounts, and AWS rejects any reserved concurrency at the floor | The four auditor modules take `reserved_concurrent_executions`. Defaults are unchanged; `-1` reserves none. |
| IAM Identity Center has no FIPS endpoints in the commercial partition: `sso-fips.<region>` and `identitystore-fips.<region>` do not resolve | The Identity Center auditor's `sso-admin` and `identitystore` clients no longer follow `AWS_USE_FIPS_ENDPOINT`. Its other clients still do. |
| PostgreSQL 15 and later already default `rds.force_ssl` to 1, so RDS reports the parameter as `pending-reboot` and every later plan showed the parameter group as changed | `rds-postgres-hardened` sets `apply_method = "pending-reboot"` on that parameter. The next plan was empty. |

## Later run: service-role trust conditions

On 2026-10-06 the service-role trust policies gained `aws:SourceAccount`
and `aws:SourceArn` conditions. Three modules from the member stack were
applied again to the same sandbox account, with `-target`, to check that
each service can still assume its role. Terraform created all 30 planned
resources.

| Role | Condition read back from IAM | Check | Result |
|---|---|---|---|
| `trust-policy-auditor` Lambda execution role | `aws:SourceAccount` | Invoked the function | Status 200, one account scanned, no errors |
| `network-perimeter-vpc` flow logs role | `aws:SourceAccount`, `aws:SourceArn` like `vpc-flow-log/*` | Flow log status, then log streams | `ACTIVE`, delivery `SUCCESS`, streams written for two network interfaces |
| `rds-postgres-hardened` Enhanced Monitoring role | `aws:SourceAccount`, `aws:SourceArn` of the DB instance | Monitoring stream in `RDSOSMetrics` | Streams for the primary and the standby, both receiving events |

The other three auditor modules use the same Lambda trust statement and
were not deployed in this run. `rds-access-auditor` was invoked under it
in the [data-plane run](#later-run-data-plane).

## Later run: data plane

On 2026-10-07 the member stack was applied again with two additions, so
that the modules could be used and not only read back: a REST API with a
mock method attached to the web ACL, and a function inside the VPC that
connects to the hardened database
([`proof/member/dataplane.tf`](../proof/member/dataplane.tf)).
[`dataplane_probe.py`](../proof/member/dataplane_probe.py) ran 13 checks
and all 13 passed. Its raw output is in
[`proof/dataplane-run.json`](proof/dataplane-run.json).

| Module | Check | Result |
|---|---|---|
| `ecr-hardened` | An image was pushed under the tag `v1` | pass |
| `ecr-hardened` | A second, different image under `v1` was rejected with `ImageTagAlreadyExistsException` | pass |
| `ecr-hardened` | The push started a scan | pass (see below) |
| `waf-hardened` | A plain request through the web ACL returned 200 | pass |
| `waf-hardened` | A cross-site scripting query string returned 403 (common rule set) | pass |
| `waf-hardened` | A Log4j lookup in a header returned 403 (known bad inputs) | pass |
| `waf-hardened` | The log recorded allowed and blocked requests, with the `authorization` value written as `REDACTED` and the bearer value sent absent from the log | pass |
| `rds-postgres-hardened` | A connection without TLS was refused: `no pg_hba.conf entry ... no encryption` | pass |
| `rds-postgres-hardened` | A TLS connection verified against the RDS certificate bundle was accepted, on TLS 1.3 with `TLS_AES_256_GCM_SHA384` | pass |
| `rds-postgres-hardened` | A database user in `rds_iam` signed in with an IAM token | pass |
| `rds-postgres-hardened` | The same user was refused with a password | pass |
| `rds-postgres-hardened` | The same token was refused without TLS | pass |
| `rds-access-auditor` | All five queries of `audit_postgres_roles.sql` ran on RDS PostgreSQL 16.3, which until now had run only against a PostgreSQL container in CI | pass |

The image was built and pushed with the ECR API, without Docker, and holds
one text file. The scan that the push started therefore ended as `FAILED`
with `UnsupportedImageError`: there is no operating system in it to scan.
That shows scan-on-push fires; it does not show findings on a real image.

The modules needed no changes. Two things about probing them are worth
knowing:

- A PostgreSQL driver may fall back to TLS on its own. `pg8000` treats
  `ssl_context=None` as "use TLS if the server offers it", so the first
  attempt at a connection without TLS succeeded, over TLS. The probe
  passes `False`, which sends no TLS request at all.
- `SHOW rds.force_ssl` is not available inside the engine. The setting is
  read from the parameter group, and its effect from the refused
  connection.

`probe.py` was run again on the same deployment: 16 of 17 checks passed,
the exception being the account-level S3 public access block described
under [What the run could not do](#what-the-run-could-not-do). That run
invoked the `rds-access-auditor` function under the `aws:SourceAccount`
trust condition added on 2026-10-06, with the same three findings on the
weak fixture and none on the hardened instance.

## Later run: patching, flow logs and access control

On 2026-10-10 three small stacks covered two modules that had not been
deployed, one Moderate stack, and one statement of `org-cloudtrail`:

- [`proof/patching`](../proof/patching/main.tf), in the sandbox member
  account: `ssm-patching-hardened` with one Amazon Linux 2023 instance in
  the patch group, in private subnets that reach AWS only through
  `fips-vpc-endpoints`, and `moderate/network-boundary/vpc-flow-logs` on
  the same VPC. The patch window was set to open every 15 minutes.
- [`proof/cloudtrail-key`](../proof/cloudtrail-key/main.tf), in the same
  account, applied with `-target`: the `org-cloudtrail` key and the trail's
  log group, without a trail.
- [`proof/access-control`](../proof/access-control/main.tf), in the
  management account: `iam-access-control`, and a role whose permissions
  boundary is the module's developer boundary. In the run its identity
  policy was `ReadOnlyAccess`; the stack now allows only the three calls
  the probe makes.

[`controls_probe.py`](../proof/controls_probe.py) ran 12 checks. On the
final run all 12 passed. Raw output:
[`patching-run-3.json`](proof/patching-run-3.json),
[`cloudtrail-key-run.json`](proof/cloudtrail-key-run.json) and
[`access-control-run.json`](proof/access-control-run.json).

| Module | Check | Result |
|---|---|---|
| `ssm-patching-hardened` | The instance registered as a managed node through the VPC endpoints | pass |
| `ssm-patching-hardened` | The `FedRAMPCompliance` patch group resolves to the module's baseline | pass |
| `ssm-patching-hardened` | `AWS-RunPatchBaseline` scanned the node under the module's baseline: 139 installed, 0 missing | pass |
| `ssm-patching-hardened` | Run Command output reached the bucket, encrypted with its customer managed key | pass |
| `ssm-patching-hardened` | The maintenance-window role trust carries `aws:SourceAccount` and `aws:SourceArn` | pass |
| `ssm-patching-hardened` | A window opened during the run and its patch task finished `SUCCESS` under that role | pass |
| `vpc-flow-logs` | The log-delivery grant on the key carries `aws:SourceAccount` and `aws:SourceArn` | pass |
| `vpc-flow-logs` | Flow log status `ACTIVE`, delivery `SUCCESS`, records in the bucket encrypted with its customer managed key | pass |
| `org-cloudtrail` | CloudWatch Logs created the trail log group under the trail key, and one event was written and read back | pass |
| `iam-access-control` | Both analyzers are `ACTIVE`: one `ACCOUNT`, one `ACCOUNT_UNUSED_ACCESS` | pass |
| `iam-access-control` | The role under the developer boundary read a bucket its account owns | pass |
| `iam-access-control` | The same role was refused `ec2:DescribeVpcs` and `iam:ListRoles`, which its identity policy allows | pass |

### What this run changed

Each of these came from the run and is fixed in the same change that adds
this section. The patching stack was probed three times:
[run 1](proof/patching-run-1.json) with no extra policy on the instance,
[run 2](proof/patching-run-2.json) with the new one, and run 3 after the
key policy was trimmed. The error texts quoted here come from the
Terraform apply output and from the maintenance-window task invocation's
status details; the probe output records only that the check failed.

| Found | Change |
|---|---|
| With a 17-character VPC ID, the flow-log access-log bucket name is 70 characters; S3 allows 63 | `vpc-flow-logs` uses a shorter name when the long one does not fit. Names that already fit are unchanged. |
| Run 1: the patch scan reported `Success`, but its output never reached the bucket. SSM Agent uploads output with the managed node's instance profile, which had no access to the bucket or its key | `ssm-patching-hardened` outputs `patch_log_writer_policy_arn`, a policy to attach to instance profile roles. The key policy no longer grants the maintenance-window role, which never writes there. |
| Run 1: the window opened and its task failed: "The provided role does not contain the iam:PassRole permission, which is required when providing a role as a task parameter." The window role was also passed as Run Command's notification role | The task no longer sets `service_role_arn` in `run_command_parameters`. No notification is configured, so nothing used it. |
| On a first apply, registering the task was refused with an `iam:PassRole` error two seconds after IAM created the role. The same apply succeeded minutes later | The task is ordered after the bucket's lifecycle configuration, which takes about a minute. |
| IAM rejected the developer boundary: "Resource vendor must be fully qualified and cannot contain regexes." Its allow statement used `arn:aws:*:*:<account>:*` | The boundary lists one ARN per service. |

The source conditions added in this change held up: Systems Manager
assumed the maintenance-window role and ran the task, and log delivery
used the flow-log key.

### What this run did not cover

- **The CloudTrail role for CloudWatch Logs.** Its trust has no source
  condition, and testing one needs an organization trail. Only the key
  and the log group were created.
- **Installing a patch.** The node had nothing missing, so the window's
  `Install` task succeeded without installing anything.
- **Patch output over 5 MiB.** S3 uploads it in parts, which also needs
  `kms:Decrypt`. The writer policy grants it; the run's output was small.
- **Actions with no resource to name.** `s3:ListAllMyBuckets` and similar
  list calls were not tried under the developer boundary.
- **`iam-access-control` in a member account.** The organization's SCP
  denies `access-analyzer:DeleteAnalyzer` there, so the stack ran in the
  management account, where it could be destroyed.

## What the run could not do

- **S3 account-level public access block.** The organization's own SCP
  denies `s3:PutAccountPublicAccessBlock` to everyone in a member account
  except the exempt roles, so `account-baseline` could not create it as the
  account administrator. Where an SCP protects that setting, apply
  `account-baseline` with an exempt role, or set the block for the whole
  organization with an S3 policy in AWS Organizations.
- **`stale-account-detector` 1.x.** AWS rejected its event data store:
  "CloudTrail Lake is no longer accepting new customers." The module was
  redesigned as 2.0, which reads IAM last-used data and CloudTrail event
  history, and deployed on 2026-10-05 (see Results).
- **Cross-account trust in a single account.** `trust-policy-auditor`
  compares trusted accounts with the organization's account list. Deployed
  in a member account it cannot read that list, so it reported nothing for
  the cross-account fixture and said so in its notification: "Organization
  accounts could not be listed, so trust in accounts outside the
  organization was not checked." Deploy it in the management account or a
  delegated administrator for that check.
- **Terraform with SSO credentials and FIPS.** With
  `use_fips_endpoint = true`, the provider looks for the Identity Center
  portal at `portal.sso-fips.<region>`, which does not exist in the
  commercial partition. Export the credentials first:
  `eval "$(aws configure export-credentials --profile <profile> --format env)"`.
- **Instance class.** `db.t4g.micro` cannot be ordered for PostgreSQL 16.3,
  the version the module pins. The run used `db.t3.micro`.

## Not covered

- **Eight modules were not deployed:** `config-conformance-pack` (AWS
  Config is off in this organization by choice), `eks-hardened`,
  `iam-password-policy` (the same policy is applied by `account-baseline`),
  and the organization-level `guardduty-org`, `security-hub-org`,
  `org-cloudtrail`, `org-governance` and `org-scp-boundary`, which would
  have replaced settings the organization already manages elsewhere. Of
  `org-cloudtrail`, only the key and the log group were created.
- **The stale-account detector's window.** It ran with one day of
  inactivity, so its findings show that the checks work, not which access
  is really unused. The member role existed in one account only.
- **GovCloud.** The run was in the commercial partition.
- **The rest of the data plane.** No ECS task was run, the web ACL's rate
  limit and IP reputation rules were not triggered, and no image with an
  operating system was scanned. The database, the repository and the two
  managed rule groups are covered by the [later run](#later-run-data-plane).
- **The Moderate and High roots** under `moderate/`, `high/` and
  `examples/` were not applied as a whole.

## Follow-ups

From the Prowler scan of the deployed modules:

- Give the interface endpoints in `fips-vpc-endpoints` an endpoint policy
  limited to the organization.
- Move `rds-postgres-hardened` off PostgreSQL 16.3, which RDS enrolls in
  Extended Support, and make the engine version a variable.
- Create the RDS PostgreSQL log group in the module so it is KMS-encrypted.
- Add network ACLs to `network-perimeter-vpc`; the VPC currently uses the
  default allow-all ACL.

One finding is a false positive: "secret in Lambda code" matched a line of
the RDS auditor that describes a username and password finding.

## Reproduce it

```bash
# Member account
cd proof/member
cp terraform.tfvars.example terraform.tfvars   # set external_account_id
eval "$(aws configure export-credentials --profile <member-profile> --format env)"
export AWS_REGION=us-east-1
terraform init && terraform plan -out=proof.tfplan && terraform apply proof.tfplan
terraform output -json probe > probe-inputs.json
python probe.py probe-inputs.json > member-run.json

# Data plane (build the function package before the plan)
./dataplane/build.sh
terraform output -json dataplane > dataplane-inputs.json
python dataplane_probe.py dataplane-inputs.json > dataplane-run.json

# Management account, Identity Center home region
cd ../management
terraform init && terraform apply -var region=<home-region>
aws lambda invoke --function-name ftlproof-idc-auditor-audit-identity-center out.json

# Patching and flow logs (member account)
cd ../patching
terraform init && terraform plan -out=proof.tfplan && terraform apply proof.tfplan
terraform output -json probe > probe-inputs.json
python ../controls_probe.py probe-inputs.json > patching-run.json
python ../controls_probe.py probe-inputs.json --empty-buckets   # before destroy

# Trail key and log group only (member account)
cd ../cloudtrail-key
terraform init && terraform apply -target=module.org_cloudtrail.aws_cloudwatch_log_group.trail
echo '{"region":"us-east-1","cloudtrail_log_group":"ftlproof-trail-logs"}' > probe-inputs.json
python ../controls_probe.py probe-inputs.json

# Access control (an account where analyzers can be deleted)
cd ../access-control
terraform init && terraform plan -out=proof.tfplan && terraform apply proof.tfplan
terraform output -json probe > probe-inputs.json
python ../controls_probe.py probe-inputs.json
```

Teardown needs three steps Terraform cannot do alone:

```bash
# 1. Deletion protection is on, by design.
aws rds modify-db-instance --db-instance-identifier ftlproof-hardened \
  --no-deletion-protection --apply-immediately
# 2. Where an SCP denies ec2:DisableEbsEncryptionByDefault, leave the
#    setting on and drop it from state.
terraform state rm module.account_baseline.aws_ebs_encryption_by_default.this
terraform destroy
# 3. The module takes a final snapshot. Delete it when you are done.
aws rds delete-db-snapshot --db-snapshot-identifier ftlproof-hardened-final-snapshot
```

The stack costs a few cents an hour, mostly the two database instances and
the interface endpoints. KMS keys stay in pending deletion for 30 days.
