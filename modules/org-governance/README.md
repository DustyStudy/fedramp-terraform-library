# org-governance

Three organization-level policies: a workload-perimeter SCP (deny root
usage, deny direct internet gateways, deny local IAM users, protect S3
Object Lock settings), an AI-services opt-out policy, and a centralized
AWS Backup policy. Deploy from the AWS Organizations management account.

## Usage

```hcl
module "org_governance" {
  source                    = "../../modules/org-governance"
  target_ou_or_account_ids  = ["ou-xxxx-xxxxxxxx"]
  backup_retention_days     = 365
  backup_regions            = ["us-east-1", "us-west-2"]
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-2, AC-4, AU-9, CP-9, MP-2 | KSI-IAM-02, KSI-CNBC-01 |

## Notes

- The centralized backup policy sets schedule and retention only — it
  does **not** enable AWS Backup Vault Lock (immutable/WORM backups).
  Vault Lock is a separate, deliberate step (it has an irreversible
  compliance mode) that this module doesn't take on your behalf; add it
  explicitly if your SSP requires immutable backups.
- The backup policy's `iam_role_arn` uses `$account` — a literal,
  un-braced AWS Backup Organizations Policy substitution placeholder that
  resolves per-account at evaluation time. That's intentional; it's not a
  broken Terraform interpolation.
- `DenyLocalIAMUsersAndAccessKeys` assumes you're provisioning human/app
  access through IAM Identity Center (SSO) instead. If any workload still
  depends on local IAM users or long-lived access keys, this SCP will
  break it — migrate first, or scope the deny down before attaching.
- `authorized_security_admin_arns` defaults to an empty list, meaning
  *no one* is exempt from the Object Lock protection statement by default.
  Populate it with your actual break-glass/security-admin role ARNs
  before attaching this in a real account, or legitimate retention
  management will be denied along with everything else.
