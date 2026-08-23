# Enforces an IAM account password policy meeting FedRAMP Moderate/High
# expectations. Note: this only governs IAM users with console passwords —
# it does not apply to SSO/Identity Center users, whose password/MFA
# policy is governed by the connected identity provider.
#
# Unlike the CloudFormation version of this library, this IS a native
# Terraform resource (aws_iam_account_password_policy) — no Lambda-backed
# custom resource needed.
#
# Control mapping:
#   Rev5 (Moderate/High): IA-5(1), AC-2, AC-7
#   FedRAMP 20x: KSI-IAM-01 (strong authentication), KSI-IAM-02 (credential lifecycle)

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.minimum_password_length
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = var.max_password_age
  password_reuse_prevention      = var.password_reuse_prevention
  hard_expiry                    = false
}
