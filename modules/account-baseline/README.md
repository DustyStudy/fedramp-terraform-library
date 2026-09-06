# account-baseline

Account-wide baseline hardening: S3 account public access block, EBS
default encryption (optionally with a customer-managed KMS key), a strict
IAM password policy, and optional adoption/lockdown of the default VPC and
its default security group. Deploy in every member account.

## Usage

```hcl
module "account_baseline" {
  source = "../../modules/account-baseline"

  minimum_password_length   = 14
  max_password_age          = 60
  password_reuse_prevention = 24
  manage_default_vpc        = true
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-2, IA-5, MP-2, CM-7, SC-28 | KSI-IAM-01, KSI-SVC-01 |

## Notes

- `kms_key_arn` is optional. Leave it unset and EBS default encryption
  still enables with the AWS-managed key; pass a CMK ARN (see
  `../../high/account-baseline` for an example that provisions one) if
  your SSP requires customer-managed keys for encryption at rest.
- `manage_default_vpc` adopts the account's default VPC via
  `aws_default_vpc` specifically so this module can strip all rules from
  its default security group. If your account has already imported or
  otherwise manages the default VPC elsewhere, set this to `false` to
  avoid a resource conflict.
- This only sets the password policy for IAM *users*. SSO/Identity Center
  users authenticate through your IdP, so password/MFA enforcement for
  them lives there, not here — see `moderate/iam-access-control` for the
  MFA-group side of that.
