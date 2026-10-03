# account-baseline

Account-wide baseline hardening: S3 account public access block, EBS
default encryption (optionally with a customer-managed KMS key), an IAM
password policy with NIST SP 800-63B-4 defaults, the AWS Backup vault that
`org-governance`'s backup policy writes to, and optional adoption/lockdown of
the default VPC and its default security group. Deploy in every member
account, and once per region listed in the backup policy's `backup_regions`.

## Usage

```hcl
module "account_baseline" {
  source = "../../modules/account-baseline"

  minimum_password_length   = 15
  max_password_age          = 0  # NIST SP 800-63B-4: no periodic expiry
  password_reuse_prevention = 24
  manage_default_vpc        = true
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-2, IA-5, MP-2, CM-7, SC-28 | KSI-IAM-APM, KSI-SVC-SIN |

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
  them lives there, not here — see `modules/iam-access-control` for the
  MFA-group side of that.
- **Backup vault.** `create_backup_vault` (default `true`) creates
  `backup_vault_name` (default `FedRAMPComplianceVault`), encrypted with a
  dedicated rotating CMK unless you pass `backup_vault_kms_key_arn`.
  `org-governance`'s backup policy targets this vault by name, so without it
  the org backup jobs fail. The vault is created in the provider's region
  only: deploy the module once per region in `backup_regions`, and in the
  `copy_destination_region` if you set one.
- **Password defaults follow NIST SP 800-63B-4**, which FedRAMP's IA-5
  guidance points to: a 15-character minimum (8 is allowed only when the
  password is always used with MFA), no composition rules, and no periodic
  expiry (800-63B-4 says verifiers "SHALL NOT impose other composition rules"
  and "SHALL NOT require subscribers to change passwords periodically").
  `require_uppercase_characters`/`require_lowercase_characters`/
  `require_numbers`/`require_symbols` and `max_password_age` remain
  available if your own policy still requires them. Checkov's CIS-style
  checks CKV_AWS_9/11/12/14/15 are skipped with that citation.
- IAM password policies can't check a blocklist of common or compromised
  passwords, so IA-5(1)(a)–(b) need an IdP that does (prefer Identity
  Center over IAM users).
