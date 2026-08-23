module "account_baseline" {
  source = "../../modules/account-baseline"

  minimum_password_length   = 14
  max_password_age          = 60
  password_reuse_prevention = 24
  manage_default_vpc        = var.manage_default_vpc
}
