# Reusable customer-managed KMS key (CMK) with rotation enabled, for
# encrypting data at rest in services that don't warrant a dedicated key
# (general-purpose S3 buckets, EBS volumes, RDS instances, etc). Deploy
# one per workload or data-classification tier rather than sharing a
# single key across unrelated systems.
#
# Control mapping:
#   Rev5 (Moderate/High): SC-12, SC-13, SC-28
#   FedRAMP 20x: KSI-SVC-02 (encryption at rest)

locals {
  account_id     = data.aws_caller_identity.current.account_id
  has_admin_role = var.admin_role_arn != ""
  has_key_users  = length(var.key_user_role_arns) > 0
}

data "aws_iam_policy_document" "cmk" {
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = local.has_admin_role ? [1] : []
    content {
      sid    = "AllowDesignatedKeyAdmin"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = [var.admin_role_arn]
      }
      actions = [
        "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
        "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
        "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.has_key_users ? [1] : []
    content {
      sid    = "AllowKeyUsage"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.key_user_role_arns
      }
      actions = [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey",
      ]
      resources = ["*"]
    }
  }
}

resource "aws_kms_key" "this" {
  description         = "Customer-managed key for ${var.key_alias}"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.cmk.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.this.key_id
}
