# The security (delegated administrator) account. guardduty-org and
# security-hub-org must run there, not in the management account.
data "aws_partition" "current" {}

provider "aws" {
  alias             = "security"
  use_fips_endpoint = var.use_fips_endpoint

  assume_role {
    role_arn = "arn:${data.aws_partition.current.partition}:iam::${var.security_account_id}:role/${var.security_account_role_name}"
  }
}
