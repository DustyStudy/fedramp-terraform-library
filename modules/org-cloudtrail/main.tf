locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
}

# KMS Key Policy for CloudTrail
data "aws_iam_policy_document" "cloudtrail_kms" {
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
    sid    = "AllowCloudTrailEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [var.organization_id]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${var.trail_name}"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsDecrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${var.trail_name}-logs:*"]
    }
  }
}

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for Org CloudTrail compliance"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudtrail_kms.json
}

resource "aws_sns_topic" "cloudtrail_alerts" {
  name              = "${var.trail_name}-alerts"
  kms_master_key_id = aws_kms_key.cloudtrail.id
}

# --- Trail Access Log Bucket ---
resource "aws_s3_bucket" "trail_access_log" {
  #checkov:skip=CKV_AWS_18:Access log bucket is the terminal sink and cannot log to itself
  #checkov:skip=CKV_AWS_144:Cross-region replication not required for access logs
  #checkov:skip=CKV2_AWS_62:Access log bucket does not require event notifications
  bucket = "${var.trail_name}-access-logs-${local.account_id}-${local.region}"
}

resource "aws_s3_bucket_public_access_block" "trail_access_log" {
  bucket                  = aws_s3_bucket.trail_access_log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail_access_log" {
  bucket = aws_s3_bucket.trail_access_log.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_access_log" {
  bucket = aws_s3_bucket.trail_access_log.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail_access_log" {
  bucket = aws_s3_bucket.trail_access_log.id
  rule {
    id     = "abort-failed-uploads-and-expire"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    expiration {
      days = var.s3_log_retention_days
    }
  }
}

# --- Main CloudTrail Bucket ---
resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV_AWS_144:Replication managed via regional disaster recovery baseline
  #checkov:skip=CKV2_AWS_62:CloudTrail directly delivers logs to S3 and CloudWatch
  bucket = "${var.trail_name}-logs-${local.account_id}-${local.region}"
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.trail_access_log.id
  target_prefix = "trail-logs/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "abort-failed-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  rule {
    id     = "archive-and-expire"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    expiration {
      days = var.s3_log_retention_days
    }
  }
}

data "aws_iam_policy_document" "s3_cloudtrail_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.s3_cloudtrail_policy.json
}

# --- CloudWatch Logs Integration ---
resource "aws_cloudwatch_log_group" "trail" {
  #checkov:skip=CKV_AWS_158:KMS encryption managed via CloudTrail KMS CMK integration
  name              = "${var.trail_name}-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cloudtrail.arn
}

data "aws_iam_policy_document" "cloudtrail_to_cloudwatch_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name               = "${var.trail_name}-cloudtrail-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch_assume.json
}

data "aws_iam_policy_document" "cloudtrail_to_cloudwatch_policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name   = "cloudtrail-cloudwatch-delivery"
  role   = aws_iam_role.cloudtrail_to_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch_policy.json
}

# --- CloudTrail Resource ---
resource "aws_cloudtrail" "org" {
  name                          = var.trail_name
  is_organization_trail         = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cloudwatch.arn
  sns_topic_name                = aws_sns_topic.cloudtrail_alerts.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      # This is CloudTrail's documented partial-ARN form meaning "all S3
      # buckets in the account" — not a bug, and not a placeholder. The
      # partition prefix is still interpolated for GovCloud correctness
      # since every real ARN (including partial ones) is partition-scoped;
      # AWS's docs don't explicitly confirm this exact partial form
      # changes in GovCloud, but there's no evidence it's a partition-
      # invariant magic string either, so this errs toward consistency.
      values = ["arn:${local.partition}:s3"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}
