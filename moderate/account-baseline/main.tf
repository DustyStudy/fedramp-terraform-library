module "account_baseline" {
  source = "../../modules/account-baseline"

  minimum_password_length   = 15
  max_password_age          = 0 # NIST SP 800-63B-4: no periodic expiry
  password_reuse_prevention = 24
  manage_default_vpc        = var.manage_default_vpc
}
