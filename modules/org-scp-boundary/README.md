# org-scp-boundary

A region-lock SCP that also denies disabling security/audit services
(CloudTrail, Config, GuardDuty, Security Hub, KMS key deletion), denies
leaving the organization, and denies unencrypted transport to S3/SQS/
DynamoDB. Deploy from the AWS Organizations management account.

## Usage

```hcl
module "org_scp_boundary" {
  source                    = "../../modules/org-scp-boundary"
  policy_name               = "fedramp-moderate-authorization-boundary"
  approved_regions          = ["us-east-1", "us-west-2"]
  target_ou_or_account_ids  = ["ou-xxxx-xxxxxxxx"]
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-3, AC-4, AC-6, SC-7, SC-8 | KSI-CNBC-01, KSI-CNBC-02 |

## Notes

- The region lock (`DenyUnapprovedRegions`) explicitly excludes global
  services (`iam`, `organizations`, `route53`, `cloudfront`, `support`,
  `aws-portal`, `budgets`) via `not_actions` — without that exclusion list
  a region-lock SCP will lock you out of managing IAM and Organizations
  entirely, since those APIs don't run "in" a region the way EC2 or S3 do.
- `approved_regions` defaults to standard AWS commercial regions
  (`us-east-1`, `us-west-2`). If you're deploying in AWS GovCloud,
  override with GovCloud region names (`us-gov-west-1`, `us-gov-east-1`)
  instead — the two partitions don't share regions, and the default will
  lock GovCloud accounts out of their own region.
- See `../../high/org-scp-boundary` for the same SCP with a High-track
  policy name — the boundary logic itself doesn't change between
  Moderate and High, only the naming.
