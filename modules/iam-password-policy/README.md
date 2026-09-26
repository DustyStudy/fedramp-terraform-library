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
