# The EBS default-encryption CMK now lives in modules/account-baseline. This
# keeps the key of a deployment made with library <= 3.0.0 instead of
# destroying it and creating another.
moved {
  from = aws_kms_key.ebs
  to   = module.account_baseline.aws_kms_key.ebs[0]
}

module "account_baseline" {
  source = "../../modules/account-baseline"

  minimum_password_length   = 16
  max_password_age          = 0 # NIST SP 800-63B-4: no periodic expiry
  password_reuse_prevention = 24
  manage_default_vpc        = var.manage_default_vpc
}
