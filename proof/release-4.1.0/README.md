# proof/release-4.1.0: live checks for the 4.1.0 release

Fixtures, not reference code: see [`../README.md`](../README.md). Sandbox
member account only, `us-east-1`, profile `AdministratorAccess-264524063329`
(the `profile` variable). Local state, destroy the same day (the backup
half: the next day, or see teardown).

## What it proves

Three things `terraform plan` and the module tests could not show for 4.1.0:

| Stack | Check | Passes when |
|---|---|---|
| `burst/` | The detector's `logs:GetQueryResults`, now scoped to the CloudTrail log group ARN instead of `*`, still works. | `probe.py burst-check` invokes the Lambda with no `FunctionError`. |
| `burst/` | Logs Insights accepts the denied query's post-stats `\| filter denied >= N`, and the result correlates with the secret read. | `burst-check` finds a finding for `ftl410-burst-actor` on the capture queue. |
| `backup/` | The vault access policy from `protect_backup_vault_recovery_points` denies a non-exempt principal even when its IAM policy allows the call, with Vault Lock in governance mode on the same vault. | `probe.py backup-deny` prints `PASS` three times. |

`burst/` creates its own single-region trail, log group, KMS-encrypted
bucket, the `ftl410-burst-actor` role, the `ftl410-probe` secret (the
constant `not-a-secret`) and an SQS queue subscribed to the module's topic.
It is applied whole.

`backup/` calls `modules/account-baseline`, which also manages account-wide
settings. **It is only ever planned with the `-target` list below**, which
selects the backup vault, its key, lock, policy and service role, plus the
fixtures. A plan without `-target` fails on purpose (the stack sets
`set_ebs_default_kms_key = true` with no key, which trips the module's
precondition) rather than offering to change the default EBS key.

## Run

PowerShell, from this directory. Check the target first:

```powershell
aws sts get-caller-identity --profile AdministratorAccess-264524063329   # partition aws, account 264524063329
```

### A. Burst detector

```powershell
cd burst
terraform init
terraform plan -out burst.tfplan
terraform apply burst.tfplan
terraform output -json probe | Out-File -Encoding utf8 probe-inputs.json
cd ..
python probe.py burst          # 8 denied calls and 1 secret read; prints timestamps
# wait 5-15 minutes: CloudTrail delivery to CloudWatch Logs
python probe.py burst-check    # PASS, or NO FINDING with the reason; rerun if the events were late
```

The detector looks back 60 minutes, so `burst-check` must run within about
45 minutes of `burst`. The schedule (every 15 minutes) is on, so the queue
may also hold findings from scheduled runs; they count.

### B. Backup vault

```powershell
cd backup
$targets = @(
  '-target=module.account_baseline.aws_kms_key.backup',
  '-target=module.account_baseline.aws_backup_vault.this',
  '-target=module.account_baseline.aws_iam_role.backup',
  '-target=module.account_baseline.aws_iam_role_policy_attachment.backup',
  '-target=module.account_baseline.aws_backup_vault_lock_configuration.this',
  '-target=module.account_baseline.aws_backup_vault_policy.protect',
  '-target=aws_dynamodb_table_item.backup_src',
  '-target=aws_iam_role_policy.backup_deleter'
)
terraform init
terraform plan -out backup.tfplan @targets
```

Read the plan before applying. It must say **11 to add, 0 to change, 0 to
destroy** and list nothing named `aws_ebs_*`, `aws_s3_account_public_access_block`,
`aws_iam_account_password_policy` or `aws_default_*`. Check that the vault
policy's `ArnNotLike` values include the role you are signed in as.

If `service-role/AWSBackupDefaultServiceRole` already exists in the account,
add `-var create_backup_service_role=false` to every command here (8 to add).

```powershell
terraform apply backup.tfplan
terraform output -json probe | Out-File -Encoding utf8 probe-inputs.json
cd ..
python probe.py backup-start
python probe.py backup-status   # repeat until the recovery point is COMPLETED (a few minutes)
python probe.py backup-deny     # three PASS lines
```

## Teardown

Run as the same administrator: it is the vault policy's exempt principal,
and nobody else can remove the policy, the lock or the vault.

### burst/

```powershell
cd burst
terraform destroy
```

The bucket has `force_destroy`, and the secret is deleted without a recovery
window. The two KMS keys go to pending deletion (7 and 30 days).

### backup/

A vault cannot be deleted while it holds a recovery point, and the lock
keeps the recovery point for its one-day minimum. Either:

- **Wait.** The recovery point expires on its own about a day after it was
  created (AWS Backup may take up to 8 more hours). `python probe.py
  backup-status` shows the delete time and when the vault is empty. Or
- **Remove the lock first** (governance mode allows it), then delete the
  recovery point by hand:

  ```powershell
  cd backup
  terraform destroy '-target=module.account_baseline.aws_backup_vault_lock_configuration.this'
  aws backup delete-recovery-point --backup-vault-name ftl410-vault --recovery-point-arn <arn from backup-status> --profile AdministratorAccess-264524063329 --region us-east-1
  ```

Then, with the vault empty:

```powershell
cd backup
terraform destroy @targets      # the same list as above
terraform state list            # must print nothing
```

The backup key goes to pending deletion (30 days). If this stack created
`AWSBackupDefaultServiceRole`, the destroy removes it again.

## Costs

Well under one US dollar for a day in a quiet sandbox:

- CloudTrail: this is the account's second copy of management events (the
  organization trail is the first), billed at $2.00 per 100,000 events.
- CloudWatch Logs: ingestion of those events ($0.50 per GB) and a Logs
  Insights scan every 15 minutes ($0.005 per GB scanned).
- KMS: three customer managed keys at $1 per month each, prorated; nothing
  while pending deletion.
- Secrets Manager: one secret at $0.40 per month, prorated.
- S3, SQS, SNS, Lambda, DynamoDB (one item) and the backup of it: fractions
  of a cent.
