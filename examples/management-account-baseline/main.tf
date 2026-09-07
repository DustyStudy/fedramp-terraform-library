# Management-account baseline: org-wide visibility, detection, and
# guardrails. Run once, from the AWS Organizations management account.
# See ../README.md for why this is a separate root from
# member-account-baseline/.

module "org_cloudtrail" {
  source           = "../../modules/org-cloudtrail"
  organization_id  = var.organization_id
}

module "guardduty_org" {
  source = "../../modules/guardduty-org"
}

module "security_hub_org" {
  source = "../../modules/security-hub-org"
}

module "org_scp_boundary" {
  source                    = "../../modules/org-scp-boundary"
  policy_name               = "fedramp-moderate-authorization-boundary"
  approved_regions          = var.approved_regions
  target_ou_or_account_ids  = var.target_ou_or_account_ids
}

module "org_governance" {
  source                          = "../../modules/org-governance"
  target_ou_or_account_ids        = var.target_ou_or_account_ids
  authorized_security_admin_arns  = var.authorized_security_admin_arns
}

# CIS/Security Hub CloudWatch alarms on the org trail's log group. This
# depends on org_cloudtrail's log_group_name output, which is why it
# lives here rather than in member-account-baseline: the org trail (and
# the CloudWatch Logs group receiving its management events) is a
# management-account resource.
module "logging_monitoring" {
  source                     = "../../moderate/logging-monitoring"
  cloudtrail_log_group_name = module.org_cloudtrail.log_group_name
}
