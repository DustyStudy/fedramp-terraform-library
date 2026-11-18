# Management-account baseline: org-wide visibility, detection, and
# guardrails. Run once, with AWS Organizations management account
# credentials; GuardDuty and Security Hub are configured in the security
# (delegated administrator) account through the aws.security provider in
# security-account.tf. See ../README.md for why this is a separate root
# from member-account-baseline/ and for the apply order.

module "org_cloudtrail" {
  source          = "../../modules/org-cloudtrail"
  organization_id = var.organization_id
}

# Both designations are per region: this covers the provider's region.
resource "aws_guardduty_organization_admin_account" "security" {
  admin_account_id = var.security_account_id
}

module "guardduty_org" {
  source    = "../../modules/guardduty-org"
  providers = { aws = aws.security }

  # The organization configuration fails until the designation exists.
  depends_on = [aws_guardduty_organization_admin_account.security]
}

# Designating an account turns Security Hub on in it, and the module's
# aws_securityhub_account then fails as already enabled. So the module
# enables Security Hub first, the designation follows, and the module's
# organization configuration waits for it via delegated_admin_account_id.
resource "aws_securityhub_organization_admin_account" "security" {
  admin_account_id = var.security_account_id

  depends_on = [module.security_hub_org.security_hub_account_id]
}

module "security_hub_org" {
  source    = "../../modules/security-hub-org"
  providers = { aws = aws.security }

  delegated_admin_account_id = aws_securityhub_organization_admin_account.security.id
}

module "org_scp_boundary" {
  source                   = "../../modules/org-scp-boundary"
  policy_name              = "fedramp-moderate-authorization-boundary"
  approved_regions         = var.approved_regions
  target_ou_or_account_ids = var.target_ou_or_account_ids
  exempt_principal_arns    = var.exempt_principal_arns
}

module "org_governance" {
  source                         = "../../modules/org-governance"
  target_ou_or_account_ids       = var.target_ou_or_account_ids
  authorized_security_admin_arns = var.authorized_security_admin_arns
}

# CIS/Security Hub CloudWatch alarms on the org trail's log group. This
# depends on org_cloudtrail's log_group_name output, which is why it
# lives here rather than in member-account-baseline: the org trail (and
# the CloudWatch Logs group receiving its management events) is a
# management-account resource.
module "logging_monitoring" {
  source                    = "../../modules/logging-monitoring"
  cloudtrail_log_group_name = module.org_cloudtrail.log_group_name
}
