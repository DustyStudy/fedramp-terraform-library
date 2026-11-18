# Enables AWS Security Hub with the default standards (AWS Foundational
# Security Best Practices + CIS AWS Foundations), plus organization
# auto-enrollment. Deploy from the Security Hub delegated administrator
# account.
#
# The NIST SP 800-53 Rev5 standard is subscribed in this account only.
# Member accounts get the default standards; pushing NIST to them needs
# Security Hub central configuration, which this module does not set up.
#
# Control mapping:
#   Rev5 (Moderate/High): CA-7, RA-5, SI-4
#   FedRAMP 20x: KSI-MLA-EVC (configuration persistently evaluated/tested), KSI-CNA-EIS (automated security assessment/enforcement)

data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_securityhub_account" "this" {
  enable_default_standards = true
}

resource "aws_securityhub_organization_configuration" "this" {
  auto_enable           = true
  auto_enable_standards = var.auto_enable_standards ? "DEFAULT" : "NONE"

  depends_on = [aws_securityhub_account.this]

  lifecycle {
    # Also what makes this resource wait for the designation when the
    # caller passes aws_securityhub_organization_admin_account.<name>.id.
    precondition {
      condition     = var.delegated_admin_account_id == null || var.delegated_admin_account_id == data.aws_caller_identity.current.account_id
      error_message = "This module is running in account ${data.aws_caller_identity.current.account_id}, but the Security Hub delegated administrator is ${coalesce(var.delegated_admin_account_id, "unset")}. Point the provider at the delegated administrator account."
    }
  }
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  count         = var.enable_nist_800_53 ? 1 : 0
  standards_arn = "arn:${data.aws_partition.current.partition}:securityhub:${data.aws_region.current.name}::standards/nist-800-53/v/5.0.0"

  depends_on = [aws_securityhub_account.this]
}

# Collects findings from every linked region into this one (SI-4).
resource "aws_securityhub_finding_aggregator" "this" {
  count        = var.enable_finding_aggregator ? 1 : 0
  linking_mode = "ALL_REGIONS"

  depends_on = [aws_securityhub_account.this]
}
