# iam-password-policy

Enforces an IAM account password policy meeting FedRAMP Moderate/High
expectations.

## Usage

```hcl
module "iam_password_policy" {
  source = "../../modules/iam-password-policy"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| IA-5(1), AC-2, AC-7 | KSI-IAM-01, KSI-IAM-02 |

## Notes

- **Native resource, unlike CloudFormation.** `aws_iam_account_password_policy`
  is a real Terraform resource — the CloudFormation version of this library
  needed a Lambda-backed custom resource for the same setting, since no
  equivalent CFN resource type exists.
- Governs IAM *users* only — SSO/Identity Center users authenticate through
  your IdP, so their MFA/password enforcement lives there, not here.
