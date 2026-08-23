# Enables AWS Security Hub with the default standards (AWS Foundational
# Security Best Practices + CIS AWS Foundations), plus organization
# auto-enrollment. Deploy from the Security Hub delegated administrator
# account.
#
# Control mapping:
#   Rev5 (Moderate/High): CA-7, RA-5, SI-4
#   FedRAMP 20x: KSI-MLA-04 (continuous security posture monitoring)

resource "aws_securityhub_account" "this" {
  enable_default_standards = true
}

resource "aws_securityhub_organization_configuration" "this" {
  auto_enable           = true
  auto_enable_standards = var.auto_enable_standards ? "DEFAULT" : "NONE"

  depends_on = [aws_securityhub_account.this]
}
