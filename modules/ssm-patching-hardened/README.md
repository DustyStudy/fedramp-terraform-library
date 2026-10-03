# ssm-patching-hardened

An automated SSM patch baseline for Amazon Linux 2023 (critical/important
patches auto-approved after 7 days), a weekly maintenance window that
runs `AWS-RunPatchBaseline`, and a KMS-encrypted S3 bucket for patch
execution output.

## Usage

```hcl
module "ssm_patching_hardened" {
  source                    = "../../modules/ssm-patching-hardened"
  environment               = "prod"
  maintenance_window_cron   = "cron(0 2 ? * SUN *)"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| SI-2, AU-12 | KSI-SVC-EIS |

## Notes

- Targets instances by tag: `PatchGroup = FedRAMPCompliance`. Tag your
  EC2 instances accordingly — this module doesn't create or discover
  instances itself.
- **The patch-output KMS key policy grants the maintenance-window role
  explicitly**, not just the account root. `AmazonSSMMaintenanceWindowRole`
  (the AWS-managed policy attached to that role) does not grant KMS access
  to a customer-managed key on its own — without the explicit
  `AllowPatchLogWriterKeyUsage` statement in `main.tf`, patch output
  delivery to the SSE-KMS bucket would fail at runtime. If you swap in
  your own execution role, add the equivalent grant for it.
- Patch baseline currently covers `AMAZON_LINUX_2023` only. Add additional
  `aws_ssm_patch_baseline` resources (and corresponding maintenance-window
  tasks) for other operating systems in your fleet.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| environment | Environment identifier | `string` | `"fedramp"` | no |
| maintenance_window_cron | Cron expression for maintenance window (Default: Sunday at 02:00 AM UTC) | `string` | `"cron(0 2 ? * SUN *)"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| maintenance_window_id | SSM Maintenance Window ID |
| patch_baseline_id | SSM Patch Baseline ID |
| patch_logs_bucket_arn | S3 Bucket storing patch execution logs |
<!-- END_TF_DOCS -->
