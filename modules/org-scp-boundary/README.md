# org-scp-boundary

A region-lock SCP that also denies disabling security/audit services
(CloudTrail, Config, GuardDuty, Security Hub, KMS key deletion), denies
leaving the organization, and denies unencrypted transport to S3/SQS/
DynamoDB. Optionally (`require_imdsv2 = true`) it also denies launching
EC2 instances without IMDSv2 and denies switching an instance back to
IMDSv1. Deploy from the AWS Organizations management account.

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
| AC-3, AC-4, AC-6, SC-7, SC-8 | KSI-CNA-RNT, KSI-CNA-ULN, KSI-IAM-ELP |

## Notes

- `require_imdsv2` is off by default because it breaks any launch
  template, AMI pipeline or tool that still sets `HttpTokens` to
  `optional`. Turn it on after Security Hub control EC2.8 (instances use
  IMDSv2) reports clean. The module's tests check that the SCP with every
  statement enabled stays under the 5,120-character SCP limit.

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

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| approved_regions | List of approved FedRAMP regions. Defaults assume a standard AWS commercial deployment (us-east-1, us-west-2) — if deploying in AWS GovCloud, override with GovCloud region names (e.g. us-gov-west-1, us-gov-east-1) instead, since the two partitions don't share regions. | `list(string)` | ```[ "us-east-1", "us-west-2" ]``` | no |
| policy_name | Name of the SCP | `string` | `"fedramp-authorization-boundary-scp"` | no |
| require_imdsv2 | Add statements that deny launching an EC2 instance without IMDSv2 (HttpTokens = required) and deny switching an instance back to IMDSv1. Off by default: turning it on breaks any launch template, AMI pipeline or tool that still sets HttpTokens to optional. | `bool` | `false` | no |
| target_ou_or_account_ids | List of Organizational Units or Account IDs to attach this SCP | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| policy_arn | ARN of the created SCP |
| policy_id | ID of the created SCP |
<!-- END_TF_DOCS -->
