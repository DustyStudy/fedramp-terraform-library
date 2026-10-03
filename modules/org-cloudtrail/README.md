# org-cloudtrail

Organization-wide CloudTrail with log file validation, KMS encryption, and
CloudWatch Logs integration. Deploy from the AWS Organizations management
account or a delegated administrator account for CloudTrail.

## Usage

```hcl
module "org_cloudtrail" {
  source          = "../../modules/org-cloudtrail"
  organization_id = "o-xxxxxxxxxx"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AU-2, AU-3, AU-6, AU-9, AU-11, AU-12, SC-28 | KSI-MLA-OSM, KSI-MLA-LET |

## Notes

- The access-log bucket is a deliberate dead end — it stores server access
  logs *for* the trail bucket and does not log itself (see the `checkov:skip`
  comment in `main.tf` for why).
- `var.log_retention_days` governs the CloudWatch Logs side; `var.s3_log_retention_days`
  governs the long-term S3 archive. Moderate/High retention expectations
  differ — see `../../high/example-tfvars/` for an illustrative override.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| organization_id | AWS Organizations ID (e.g. o-xxxxxxxxxx). Required for the bucket policy trust condition. | `string` | n/a | yes |
| log_retention_days | CloudWatch Logs retention. Moderate baseline typically expects >= 90 days readily available plus 1 year total; High baseline commonly expects 3+ years total retention — confirm against your SSP. | `number` | `365` | no |
| s3_log_retention_days | S3 lifecycle retention in days for the long-term log archive (default ~7 years). Adjust to your organization's records retention schedule. | `number` | `2555` | no |
| trail_name | Name for the organization trail. | `string` | `"org-security-trail"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| access_log_bucket_name | S3 bucket storing server access logs for the CloudTrail log bucket |
| kms_key_arn | KMS key used to encrypt trail logs |
| log_bucket_name | S3 bucket storing CloudTrail logs |
| log_group_name | CloudWatch Logs group for real-time trail analysis |
| trail_arn | ARN of the organization CloudTrail |
<!-- END_TF_DOCS -->
