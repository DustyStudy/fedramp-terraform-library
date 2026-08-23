# Organization-wide CloudTrail with log file validation, encryption, and
# CloudWatch Logs integration. Deploy from the AWS Organizations management
# account or a delegated administrator account for CloudTrail.
#
# Control mapping:
#   Rev5 (Moderate/High): AU-2, AU-3, AU-6, AU-9, AU-11, AU-12, SC-28
#   FedRAMP 20x: KSI-MLA-01 (comprehensive logging), KSI-MLA-02 (log integrity)

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# --- KMS key for encrypting trail logs ---

data "aws_iam_policy_document" "cloudtrail_kms" {
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
  }
}

resource "aws_kms_key" "cloudtrail" {
  description         = "CMK for encrypting the organization CloudTrail logs (SC-28, SC-13)"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.cloudtrail_kms.json
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.trail_name}-key"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# --- Dedicated access-log bucket (terminal sink; see README for why) ---

resource "aws_s3_bucket" "trail_access_log" {
  #checkov:skip=CKV_AWS_18:This bucket IS the access-log destination for the trail bucket. A log-destination bucket logging to itself is a circular anti-pattern AWS explicitly advises against, so this is the terminal sink and intentionally has no further logging target.
  bucket = "${var.trail_name}-access-logs-${local.account_id}-${local.region}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail_access_log" {
  # S3 server access logs must land in a bucket encrypted with SSE-S3, not
  # SSE-KMS — that's an AWS platform restriction on the access-logging
  # feature itself, not a choice made here.
  bucket = aws_s3_bucket.trail_access_log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
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

resource "aws_s3_bucket_lifecycle_configuration" "trail_access_log" {
  bucket = aws_s3_bucket.trail_access_log.id
  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    expiration {
      days = var.s3_log_retention_days
    }
  }
}

data "aws_iam_policy_document" "trail_access_log_bucket" {
  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_access_log.arn}/*"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.trail.arn]
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
    resources = [aws_s3_bucket.trail_access_log.arn, "${aws_s3_bucket.trail_access_log.arn}/*"]

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

resource "aws_s3_bucket_policy" "trail_access_log" {
  bucket = aws_s3_bucket.trail_access_log.id
  policy = data.aws_iam_policy_document.trail_access_log_bucket.json
}

# --- Trail log bucket ---

resource "aws_s3_bucket" "trail" {
  bucket = "${var.trail_name}-logs-${local.account_id}-${local.region}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
  }
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
  target_prefix = "trail-log-bucket-access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "archive-and-expire"
    status = "Enabled"

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

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [var.organization_id]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [var.organization_id]
    }
  }

  statement {
    sid       = "DenyUnencryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]

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

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# --- CloudWatch Logs delivery ---

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.cloudtrail.arn
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_to_cloudwatch" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name               = "${var.trail_name}-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name   = "cloudtrail-to-cloudwatch-logs"
  role   = aws_iam_role.cloudtrail_to_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch.json
}

# --- The trail itself ---

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

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}
