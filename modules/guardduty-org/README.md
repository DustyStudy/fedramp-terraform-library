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
| SI-4, IR-4, RA-5 | KSI-MLA-03, KSI-INR-01 |

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
