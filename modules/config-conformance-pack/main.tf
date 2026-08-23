# Enables AWS Config with a continuous recorder and delivery channel, plus
# the AWS-managed Operational Best Practices for FedRAMP Moderate
# conformance pack. Deploy per-account (or via Config aggregator across
# the organization).
#
# Control mapping:
#   Rev5 (Moderate/High): CM-2, CM-6, CM-8, CA-7, RA-5
#   FedRAMP 20x: KSI-CNBC-01 (configuration management), KSI-CNBC-02 (change detection)

locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name
  bucket_name = var.config_bucket_name != "" ? var.config_bucket_name : "aws-config-${local.account_id}-${local.region}"
}

# --- Access-log bucket (terminal sink; see README for why) ---

resource "aws_s3_bucket" "config_access_log" {
  #checkov:skip=CKV_AWS_18:This bucket IS the access-log destination for the Config bucket. A log-destination bucket logging to itself is a circular anti-pattern AWS explicitly advises against, so this is the terminal sink and intentionally has no further logging target.
  bucket = "${local.bucket_name}-access-logs"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_access_log" {
  bucket = aws_s3_bucket.config_access_log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
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

data "aws_iam_policy_document" "config_access_log_bucket" {
  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_access_log.arn}/*"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.config.arn]
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
    resources = [aws_s3_bucket.config_access_log.arn, "${aws_s3_bucket.config_access_log.arn}/*"]

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

# --- AWS Config delivery bucket ---

resource "aws_s3_bucket" "config" {
  bucket = local.bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
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
  target_prefix = "config-bucket-access-logs/"
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]

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

# --- Config recorder IAM role ---

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config_recorder" {
  name               = "config-recorder-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config_recorder_managed" {
  role       = aws_iam_role.config_recorder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_s3_delivery" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]
  }
}

resource "aws_iam_role_policy" "config_s3_delivery" {
  name   = "config-s3-delivery"
  role   = aws_iam_role.config_recorder.id
  policy = data.aws_iam_policy_document.config_s3_delivery.json
}

# --- Config recorder + delivery channel ---

resource "aws_config_configuration_recorder" "default" {
  name     = "default"
  role_arn = aws_iam_role.config_recorder.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "default" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.id

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.default]
}

# The recorder resource above only creates the recorder — it must be
# separately switched on via this resource, or it will sit idle.
resource "aws_config_configuration_recorder_status" "default" {
  name       = aws_config_configuration_recorder.default.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.default]
}

# --- Conformance pack ---

resource "aws_config_conformance_pack" "fedramp_moderate" {
  name           = "fedramp-moderate-baseline"
  template_s3_uri = "s3://aws-configservice-conformancepack-templates-${local.region}/${var.conformance_pack_template}"

  depends_on = [aws_config_configuration_recorder_status.default]
}
