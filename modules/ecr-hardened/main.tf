locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# Customer-Managed KMS Key for ECR Image Encryption (FedRAMP SC-13/SC-28)
#
# Note: unlike CloudWatch Logs, ECR image push/pull operations authorize
# through the calling IAM principal (the developer, CI/CD role, or task
# execution role doing docker push/pull) rather than through a fixed
# service-principal grant on the key. Whoever needs to push or pull images
# from this repository must have kms:GenerateDataKey/kms:Decrypt on this
# key — via an IAM identity policy on their own role, or an additional
# statement here — which this module doesn't grant on its own since it
# doesn't know which principals need access.
data "aws_iam_policy_document" "ecr_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires constrained write access
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

resource "aws_kms_key" "ecr" {
  description             = "KMS CMK for FedRAMP ECR Image Repository Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ecr_kms.json
}

resource "aws_ecr_repository" "this" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 14 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Retain max 30 tagged production images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v", "prod", "release"]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
