# guardduty-org

Enables Amazon GuardDuty with organization auto-enrollment for new
accounts. Deploy from the GuardDuty delegated administrator account.

## Usage

```hcl
module "guardduty_org" {
  source = "../../modules/guardduty-org"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| SI-4, IR-4, RA-5 | KSI-CNA-EIS, KSI-INR-RPI |

## Notes

- **Native resource, unlike CloudFormation.** GuardDuty organization
  auto-enrollment is a real Terraform resource
  (`aws_guardduty_organization_configuration`) — the CloudFormation version
  of this library needed a Lambda-backed custom resource for the same
  thing, since no equivalent CFN resource type exists.
- This module enables the three long-standing protections (S3 Logs,
  Kubernetes Audit Logs, EBS Malware Protection) via the classic
  `datasources` block. GuardDuty has since added newer protections (RDS
  Protection, Lambda Protection, EKS Runtime Monitoring) that may be
  exposed differently depending on your AWS provider version — check
  current provider docs if you want those too.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| auto_enable | Deprecated: AWS provider v6 removed the auto_enable argument. Use auto_enable_organization_members instead. Kept so existing callers still plan; false must be paired with auto_enable_organization_members = "NONE". | `bool` | `true` | no |
| auto_enable_organization_members | GuardDuty auto-enablement for member accounts: NEW (accounts that join later; matches the old auto_enable = true behavior), ALL (existing members too), or NONE. | `string` | `"NEW"` | no |
| finding_publishing_frequency | How often GuardDuty publishes findings to CloudWatch Events. | `string` | `"FIFTEEN_MINUTES"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| detector_id | GuardDuty detector ID |
| findings_topic_arn | SNS topic receiving Medium+ severity findings — subscribe your incident response team or SOAR pipeline (see moderate/incident-response/ for IR automation modules). |
<!-- END_TF_DOCS -->
