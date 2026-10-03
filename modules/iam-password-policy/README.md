# iam-password-policy

Enforces an IAM account password policy with NIST SP 800-63B-4 defaults
(which FedRAMP's IA-5 guidance points to).

## Usage

```hcl
module "iam_password_policy" {
  source = "../../modules/iam-password-policy"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| IA-5(1) (partial), AC-2 | KSI-IAM-APM, KSI-IAM-AAM |

## Notes

- **Native resource, unlike CloudFormation.** `aws_iam_account_password_policy`
  is a real Terraform resource — the CloudFormation version of this library
  needed a Lambda-backed custom resource for the same setting, since no
  equivalent CFN resource type exists.
- Governs IAM *users* only — SSO/Identity Center users authenticate through
  your IdP, so their MFA/password enforcement lives there, not here.
- **Password defaults follow NIST SP 800-63B-4**, which FedRAMP's IA-5
  guidance points to: a 15-character minimum (8 is allowed only when the
  password is always used with MFA), no composition rules, and no periodic
  expiry (800-63B-4 says verifiers "SHALL NOT impose other composition rules"
  and "SHALL NOT require subscribers to change passwords periodically").
  `require_uppercase_characters`/`require_lowercase_characters`/
  `require_numbers`/`require_symbols` and `max_password_age` remain
  available if your own policy still requires them. Checkov's CIS-style
  checks CKV_AWS_9/11/12/14/15 are skipped with that citation.
- IAM password policies can't check a blocklist of common or compromised
  passwords, so IA-5(1)(a)–(b) need an IdP that does (prefer Identity
  Center over IAM users).

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| max_password_age | Days before a password must be changed; 0 disables expiry. NIST SP 800-63B-4 says verifiers SHALL NOT require periodic changes, so 0 is the default. Set a value only if your own policy requires rotation. | `number` | `0` | no |
| minimum_password_length | Minimum password length. NIST SP 800-63B-4: at least 15 for single-factor passwords; 8 only when always used with MFA. FedRAMP assigns no separate value. | `number` | `15` | no |
| password_reuse_prevention | Number of previous passwords remembered to prevent reuse (organization-defined; FedRAMP assigns no value). | `number` | `24` | no |
| require_lowercase_characters | Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules. | `bool` | `false` | no |
| require_numbers | Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules. | `bool` | `false` | no |
| require_symbols | Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules. | `bool` | `false` | no |
| require_uppercase_characters | Opt-in composition rule. NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules. | `bool` | `false` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| expire_passwords | Whether password expiration is active under this policy (true whenever max_password_age > 0) |
<!-- END_TF_DOCS -->
