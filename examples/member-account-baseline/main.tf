# Member-account baseline: run once per workload account. Assumes
# management-account-baseline/ has already been applied to the
# Organizations management account (this account inherits org-wide
# GuardDuty/Security Hub auto-enrollment and the org-governance/
# org-scp-boundary SCPs from there — nothing here re-creates those).
# See ../README.md for the two duplicate-resource conflicts this
# composition surfaced and why the choices below avoid them.

module "account_baseline" {
  source = "../../modules/account-baseline"

  minimum_password_length   = 14
  max_password_age          = 60
  password_reuse_prevention = 24
  # Adopts this account's default VPC and strips its default security
  # group. Do NOT also deploy
  # moderate/network-boundary/default-security-group-lockdown against
  # the same default VPC — both manage aws_default_security_group and
  # will fight each other. Skip iam-password-policy here too: it and
  # account-baseline both create aws_iam_account_password_policy.
  manage_default_vpc = true
}

module "network_perimeter_vpc" {
  source              = "../../modules/network-perimeter-vpc"
  environment         = var.environment
  vpc_cidr            = var.vpc_cidr
  availability_zones  = var.availability_zones
  public_subnet_cidrs = var.public_subnet_cidrs
  app_subnet_cidrs    = var.app_subnet_cidrs
  db_subnet_cidrs     = var.db_subnet_cidrs
  log_retention_days  = var.log_retention_days
  # This module's own Flow Logs cover this VPC already — don't also
  # attach moderate/network-boundary/vpc-flow-logs to it. That module is
  # for a VPC that didn't come from this module (e.g. a pre-existing
  # legacy VPC in the account).
}

module "config_conformance_pack" {
  source = "../../modules/config-conformance-pack"
}

module "iam_access_control" {
  source        = "../../moderate/iam-access-control"
  analyzer_type = "ACCOUNT"
}

module "incident_notifications" {
  source                       = "../../moderate/incident-response/incident-notifications"
  guardduty_severity_threshold = 7
}
