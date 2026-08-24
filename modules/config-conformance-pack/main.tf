locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name
  bucket_name = var.config_bucket_name
  partition   = data.aws_partition.current.partition
}

# KMS Key Policy for AWS Config
data "aws_iam_policy_document" "config_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative and service operations require root wildcard scoping
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

  statement {
    sid    = "AllowConfigServiceEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:config:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_kms_key" "config" {
  description             = "KMS key for AWS Config compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.config_kms.json
}

# --- Access Logs Bucket ---
resource "aws_s3_bucket" "config_access_log" {
  #checkov:skip=CKV_AWS_18:Access log bucket is the terminal sink and cannot log to itself
  #checkov:skip=CKV_AWS_144:Cross-region replication not required for access logs
  #checkov:skip=CKV2_AWS_62:Access log bucket does not require event notifications
  bucket = "${local.bucket_name}-access-logs"
}

resource "aws_s3_bucket_public_access_block" "config_access_log" {
  bucket                  = aws_s3_bucket.config_access_log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.config.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  rule {
    id     = "abort-failed-uploads-and-expire"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    expiration {
      days = 365
    }
  }
}

# --- Main Config S3 Bucket ---
resource "aws_s3_bucket" "config" {
  #checkov:skip=CKV_AWS_144:Replication managed via regional disaster recovery baseline
  #checkov:skip=CKV2_AWS_62:Config delivery mechanism writes directly without notifications
  bucket = local.bucket_name
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "config" {
  bucket        = aws_s3_bucket.config.id
  target_bucket = aws_s3_bucket.config_access_log.id
  target_prefix = "config-bucket-logs/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.config.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    id     = "abort-and-transition"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    expiration {
      days = 365
    }
  }
}

# --- Conformance Pack Resource ---
resource "aws_config_conformance_pack" "fedramp_moderate" {
  name          = "fedramp-moderate-pack"
  template_body = var.conformance_pack_template
  depends_on    = [aws_s3_bucket.config]
}
