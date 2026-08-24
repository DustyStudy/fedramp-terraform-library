locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

# Customer-Managed Key dedicated to default EBS encryption for High baseline
data "aws_iam_policy_document" "ebs_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "ebs" {
  description             = "Dedicated KMS CMK for FedRAMP High EBS default encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ebs_kms.json
}

module "account_baseline" {
  source = "../../modules/account-baseline"

  kms_key_arn               = aws_kms_key.ebs.arn
  minimum_password_length   = 16
  max_password_age          = 60
  password_reuse_prevention = 24
  manage_default_vpc        = var.manage_default_vpc
}
