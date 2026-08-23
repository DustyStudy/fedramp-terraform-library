# Enables VPC Flow Logs (all traffic) delivered to an encrypted,
# access-logged S3 bucket for an existing VPC. Deploy once per VPC.
#
# Note: if you used modules/network-perimeter-vpc to create your VPC,
# that module already includes Flow Logs (to CloudWatch Logs) and does
# not need this module layered on top. Use this one for a VPC that
# already exists and wasn't created through that module, or if you
# specifically want an S3 destination instead of CloudWatch Logs.
#
# Control mapping:
#   Rev5 (Moderate/High): SC-7, AU-2, AU-12
#   FedRAMP 20x: KSI-CNBC-02 (network boundary monitoring), KSI-MLA-01 (comprehensive logging)

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# --- Access-log bucket (terminal sink; see README for why) ---

resource "aws_s3_bucket" "flow_log_access_log" {
  #checkov:skip=CKV_AWS_18:This bucket IS the access-log destination for the flow log bucket. A log-destination bucket logging to itself is a circular anti-pattern AWS explicitly advises against, so this is the terminal sink and intentionally has no further logging target.
  #checkov:skip=CKV_AWS_145:S3 server access logs must land in a bucket encrypted with SSE-S3, not SSE-KMS — that's an AWS platform restriction on the access-logging feature itself, not a choice made here.
  bucket = "vpc-flow-logs-access-logs-${local.account_id}-${local.region}-${var.vpc_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "flow_log_access_log" {
  bucket = aws_s3_bucket.flow_log_access_log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "flow_log_access_log" {
  bucket                  = aws_s3_bucket.flow_log_access_log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "flow_log_access_log" {
  bucket = aws_s3_bucket.flow_log_access_log.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_log_access_log" {
  bucket = aws_s3_bucket.flow_log_access_log.id
  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    expiration {
      days = var.log_retention_days
    }
  }
}

data "aws_iam_policy_document" "flow_log_access_log_bucket" {
  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.flow_log_access_log.arn}/*"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.flow_log.arn]
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
    resources = [aws_s3_bucket.flow_log_access_log.arn, "${aws_s3_bucket.flow_log_access_log.arn}/*"]

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

resource "aws_s3_bucket_policy" "flow_log_access_log" {
  bucket = aws_s3_bucket.flow_log_access_log.id
  policy = data.aws_iam_policy_document.flow_log_access_log_bucket.json
}

# --- Flow log delivery bucket ---

# Note: VPC Flow Logs delivered to S3 support SSE-KMS, but with two
# specific requirements: the key must be referenced by full ARN (a key ID
# causes a silent "LogDestination undeliverable" failure — a known AWS
# platform quirk, not a typo), and the delivery.logs.amazonaws.com
# service principal needs explicit key policy permissions, same as any
# other AWS log-delivery service using a customer-managed key.
data "aws_iam_policy_document" "flow_log_kms" {
  #checkov:skip=CKV_AWS_109:KMS root account scoping
  #checkov:skip=CKV_AWS_111:KMS key management write access
  #checkov:skip=CKV_AWS_356:KMS key policy wildcard scoping
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
    sid    = "AllowFlowLogDeliveryEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "flow_log" {
  description         = "KMS key for VPC Flow Logs S3 delivery bucket"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.flow_log_kms.json
}

resource "aws_kms_alias" "flow_log" {
  name          = "alias/vpc-flow-logs-${var.vpc_id}"
  target_key_id = aws_kms_key.flow_log.key_id
}

resource "aws_s3_bucket" "flow_log" {
  bucket = "vpc-flow-logs-${local.account_id}-${local.region}-${var.vpc_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "flow_log" {
  bucket = aws_s3_bucket.flow_log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      # Must be the full key ARN, not a bare key ID — AWS's own docs warn
      # that a key ID causes flow log delivery to fail with an
      # undeliverable-destination error rather than a clear KMS error.
      kms_master_key_id = aws_kms_key.flow_log.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "flow_log" {
  bucket                  = aws_s3_bucket.flow_log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "flow_log" {
  bucket = aws_s3_bucket.flow_log.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "flow_log" {
  bucket        = aws_s3_bucket.flow_log.id
  target_bucket = aws_s3_bucket.flow_log_access_log.id
  target_prefix = "flow-log-bucket-access-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_log" {
  bucket = aws_s3_bucket.flow_log.id
  rule {
    id     = "archive-and-expire"
    status = "Enabled"
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    expiration {
      days = var.log_retention_days
    }
  }
}

data "aws_iam_policy_document" "flow_log_bucket" {
  statement {
    sid    = "AWSLogDeliveryWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.flow_log.arn}/AWSLogs/${local.account_id}/*"]

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
    sid    = "AWSLogDeliveryAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.flow_log.arn]

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
    resources = [aws_s3_bucket.flow_log.arn, "${aws_s3_bucket.flow_log.arn}/*"]

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

resource "aws_s3_bucket_policy" "flow_log" {
  bucket = aws_s3_bucket.flow_log.id
  policy = data.aws_iam_policy_document.flow_log_bucket.json
}

resource "aws_flow_log" "this" {
  vpc_id                   = var.vpc_id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = aws_s3_bucket.flow_log.arn
  max_aggregation_interval = 600

  depends_on = [aws_s3_bucket_policy.flow_log]
}
