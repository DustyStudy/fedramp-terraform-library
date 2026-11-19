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
  target_ou_or_account_ids  = ["ou-xxxx-xxxxxxxx"]
  exempt_principal_arns     = ["arn:<partition>:iam::*:role/terraform-deployer"]
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

- `DenyMfaRemovalWithoutMfa` denies `iam:DeactivateMFADevice`,
  `iam:DeleteVirtualMFADevice` and `iam:ResyncMFADevice` unless the caller
  signed in with MFA (`BoolIfExists aws:MultiFactorAuthPresent = false`), so
  a stolen password or access key cannot strip the second factor. Enrolment
  actions are not denied, because first enrolment has no MFA. Users in
  `modules/iam-access-control` have MFA when they manage their own devices,
  so self-service still works. Federated/SSO sessions carry no MFA flag:
  put the role that resets users' MFA in `exempt_principal_arns`.

- The region lock (`DenyUnapprovedRegions`) explicitly excludes global
  services (`iam`, `organizations`, `route53`, `cloudfront`, `support`,
  `aws-portal`, `budgets`) via `not_actions` — without that exclusion list
  a region-lock SCP will lock you out of managing IAM and Organizations
  entirely, since those APIs don't run "in" a region the way EC2 or S3 do.
- `approved_regions` left unset follows the provider's partition:
  `us-gov-west-1` and `us-gov-east-1` in GovCloud, `us-east-1` and
  `us-west-2` elsewhere. A list that is empty or names the other
  partition's regions fails the plan, because that region lock would deny
  every regional action in the targeted accounts.
- Attaching the SCP with an empty `exempt_principal_arns` produces a plan
  warning (a `check` block, so it does not stop the apply): nobody in the
  targeted accounts, your pipeline included, can then set the S3 account
  public access block, change GuardDuty or Config, or delete a KMS key.
- See `../../high/org-scp-boundary` for the same SCP with a High-track
  policy name — the boundary logic itself doesn't change between
  Moderate and High, only the naming.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| approved_regions | Regions the SCP allows. null (the default) picks them from the partition the provider runs in: us-gov-west-1 and us-gov-east-1 in GovCloud, us-east-1 and us-west-2 elsewhere. A list must be non-empty and belong to that partition (only us-gov-* regions in GovCloud, none of them outside it), or the plan fails: a region lock naming another partition's regions denies every regional action in the targets. | `list(string)` | `null` | no |
| exempt_principal_arns | IAM role ARNs (wildcards allowed, e.g. an Identity Center permission set role "arn:<partition>:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_SecurityAdmin_*") that the security-service and account-baseline denies do not apply to. Without one, nobody in a member account, including your deployment pipeline, can create the S3 account public access block, enable GuardDuty features or delete a KMS key once the SCP is attached. | `list(string)` | `[]` | no |
| policy_name | Name of the SCP | `string` | `"fedramp-authorization-boundary-scp"` | no |
| require_imdsv2 | Add statements that deny launching an EC2 instance without IMDSv2 (HttpTokens = required) and deny switching an instance back to IMDSv1. Off by default: turning it on breaks any launch template, AMI pipeline or tool that still sets HttpTokens to optional. | `bool` | `false` | no |
| target_ou_or_account_ids | List of Organizational Units or Account IDs to attach this SCP | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| policy_arn | ARN of the created SCP |
| policy_id | ID of the created SCP |
<!-- END_TF_DOCS -->
