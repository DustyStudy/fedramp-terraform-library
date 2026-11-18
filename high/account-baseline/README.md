# high/account-baseline

Root configuration that applies
[`modules/account-baseline`](../../modules/account-baseline) with the
High-track values.

## What it deploys

- The account-level S3 public access block.
- EBS encryption by default, using a customer-managed KMS key this stack creates (rotation on,
  30-day deletion window).
- The IAM password policy: 16-character minimum, no periodic
  expiry, last 24 passwords refused.
- The AWS Backup vault `FedRAMPComplianceVault` with its own KMS key, and
  the `AWSBackupDefaultServiceRole` service role (module defaults).
- With `manage_default_vpc = true` (the default), adoption of the region's
  default VPC and removal of every rule from its default security group.

## Where to run it

In **every member account**, with that account's credentials. EBS default
encryption, the backup vault and the default VPC are per region, so apply
once per region you use, and at least in every region in the organization
backup policy's `backup_regions` (see
[`high/org-governance`](../org-governance)).

The password policy and the backup service role are account-wide. This
stack does not expose the module's `create_backup_service_role`, so for a
second region in the same account either call the module yourself with
that set to `false`, or import the existing role into that region's state.

## Inputs

None are required.

| Variable | Default | Meaning |
|---|---|---|
| `manage_default_vpc` | `true` | Adopt the default VPC and empty its default security group. Set `false` if the default VPC is managed elsewhere or has been deleted. |
| `use_fips_endpoint` | `true` | Send API calls to FIPS endpoints. |

Outputs: `s3_public_access_block_id`, `ebs_encryption_enabled`, `ebs_kms_key_arn`.

## GovCloud

Works unchanged in `us-gov-west-1` and `us-gov-east-1`. The KMS key policy builds its ARN from the current partition, and FIPS
endpoints stay on by default.

## Before you apply

- No backend is configured, so state is local until you add your own
  `backend` block. No region is set either: the provider takes it from
  `AWS_REGION` or your profile.
- Run `terraform plan` first and read it. Check the caller with
  `aws sts get-caller-identity` so you know which partition and account
  the plan is for.
