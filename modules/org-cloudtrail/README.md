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
| AU-2, AU-3, AU-6, AU-9, AU-11, AU-12, SC-28 | KSI-MLA-01, KSI-MLA-02 |

## Notes

- The access-log bucket is a deliberate dead end — it stores server access
  logs *for* the trail bucket and does not log itself (see the `checkov:skip`
  comment in `main.tf` for why).
- `var.log_retention_days` governs the CloudWatch Logs side; `var.s3_log_retention_days`
  governs the long-term S3 archive. Moderate/High retention expectations
  differ — see `../../high/example-tfvars/` for an illustrative override.
