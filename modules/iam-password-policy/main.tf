# Enforces an IAM account password policy aligned with NIST SP 800-63B-4,
# which FedRAMP's IA-5 guidance points to ("Authenticators must be compliant
# with the most recent NIST Digital Identity Guidelines"). Note: this only
# governs IAM users with console passwords — it does not apply to
# SSO/Identity Center users, whose password/MFA policy is governed by the
# connected identity provider.
#
# 800-63B-4 defaults used here: 15-character minimum for single-factor
# passwords, no composition rules ("SHALL NOT impose other composition
# rules"), and no periodic expiry ("SHALL NOT require subscribers to change
# passwords periodically"). Composition rules and expiry remain available as
# opt-in variables for organizations whose own policy still requires them.
#
# IAM password policies cannot check passwords against a blocklist of
# common or compromised values, so IA-5(1)(a)-(b) are NOT met by this module
# alone — prefer Identity Center with an IdP that performs blocklist checks.
#
# Unlike the CloudFormation version of this library, this IS a native
# Terraform resource (aws_iam_account_password_policy) — no Lambda-backed
# custom resource needed.
#
# Control mapping:
#   Rev5: IA-5(1) (partial — see above), AC-2
#   FedRAMP 20x: KSI-IAM-APM (strong/passwordless authentication), KSI-IAM-AAM (account lifecycle automation)

# Trivy AWS-0058..0061 require composition rules (CIS-era); NIST SP 800-63B-4, cited by
# FedRAMP IA-5 guidance, says verifiers SHALL NOT impose them. Opt in via require_* variables.
#trivy:ignore:AVD-AWS-0058 trivy:ignore:AVD-AWS-0059 trivy:ignore:AVD-AWS-0060 trivy:ignore:AVD-AWS-0061
resource "aws_iam_account_password_policy" "this" {
  #checkov:skip=CKV_AWS_9:NIST SP 800-63B-4 (cited by FedRAMP IA-5 guidance) says verifiers SHALL NOT require periodic password changes; expiry is opt-in via max_password_age
  #checkov:skip=CKV_AWS_11:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_lowercase_characters
  #checkov:skip=CKV_AWS_12:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_numbers
  #checkov:skip=CKV_AWS_14:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_symbols
  #checkov:skip=CKV_AWS_15:NIST SP 800-63B-4 says verifiers SHALL NOT impose composition rules; opt-in via require_uppercase_characters
  minimum_password_length        = var.minimum_password_length
  require_uppercase_characters   = var.require_uppercase_characters
  require_lowercase_characters   = var.require_lowercase_characters
  require_numbers                = var.require_numbers
  require_symbols                = var.require_symbols
  allow_users_to_change_password = true
  max_password_age               = var.max_password_age
  password_reuse_prevention      = var.password_reuse_prevention
  hard_expiry                    = false
}
