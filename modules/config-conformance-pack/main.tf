# Enables AWS Config with a continuous recorder and delivery channel, plus
# an optional conformance pack (for example AWS's Operational Best
# Practices for FedRAMP Moderate sample). Deploy once per account and region.
#
# Control mapping:
#   Rev5 (Moderate/High): CM-2, CM-6, CM-8, CA-7, RA-5
#   FedRAMP 20x: KSI-SVC-ACM, KSI-MLA-EVC

locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name
  partition   = data.aws_partition.current.partition
  bucket_name = var.config_bucket_name != "" ? var.config_bucket_name : "aws-config-${local.account_id}-${local.region}"

  # Bucket ARNs are built from names so the policies below render at plan
  # time and show up in full in plan output for review.
  bucket_arn            = "arn:${local.partition}:s3:::${local.bucket_name}"
  access_log_bucket_arn = "arn:${local.partition}:s3:::${local.bucket_name}-access-logs"

  create_conformance_pack = var.conformance_pack_template_body != null || var.conformance_pack_template_s3_uri != null
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
  #checkov:skip=CKV_AWS_145:S3 server access log destinations only support SSE-S3, not SSE-KMS
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

# S3 server access logging cannot deliver to a bucket whose default
# encryption is SSE-KMS (an AWS platform restriction on the feature), so
# this terminal sink uses SSE-S3. Log delivery would otherwise fail silently.
resource "aws_s3_bucket_server_side_encryption_configuration" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "config_access_log_bucket" {
  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${local.access_log_bucket_arn}/*"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [local.bucket_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.access_log_bucket_arn, "${local.access_log_bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  policy = data.aws_iam_policy_document.config_access_log_bucket.json
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
  #checkov:skip=CKV_AWS_144:Cross-region replication is NOT configured by this module. If your contingency plan needs off-site log copies, add S3 replication, or tag the bucket Backup=true (versioning required) and set org-governance copy_destination_region
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

  depends_on = [aws_s3_bucket_policy.config_access_log]
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [local.bucket_arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/AWSLogs/${local.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json
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

# --- Config recorder IAM role ---
data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config_recorder" {
  name               = "config-recorder-${local.region}"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config_recorder_managed" {
  role       = aws_iam_role.config_recorder.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid       = "DeliverToConfigBucket"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:PutObjectAcl"]
    resources = ["${local.bucket_arn}/AWSLogs/${local.account_id}/Config/*"]
  }

  statement {
    sid       = "CheckConfigBucketAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [local.bucket_arn]
  }

  statement {
    sid       = "EncryptWithConfigKey"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.config.arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "config-delivery"
  role   = aws_iam_role.config_recorder.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

# --- Config recorder + delivery channel ---
resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = aws_iam_role.config_recorder.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.include_global_resource_types
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_kms_key_arn = aws_kms_key.config.arn

  snapshot_delivery_properties {
    delivery_frequency = var.snapshot_delivery_frequency
  }

  depends_on = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.config]
}

# The recorder resource only creates the recorder. It stays idle until this
# resource switches it on.
resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# --- Conformance pack (optional) ---
resource "aws_config_conformance_pack" "this" {
  count = local.create_conformance_pack ? 1 : 0

  name            = var.conformance_pack_name
  template_body   = var.conformance_pack_template_body
  template_s3_uri = var.conformance_pack_template_s3_uri

  lifecycle {
    precondition {
      condition     = var.conformance_pack_template_body == null || var.conformance_pack_template_s3_uri == null
      error_message = "Set conformance_pack_template_body or conformance_pack_template_s3_uri, not both."
    }
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

moved {
  from = aws_config_conformance_pack.fedramp_moderate
  to   = aws_config_conformance_pack.this[0]
}
