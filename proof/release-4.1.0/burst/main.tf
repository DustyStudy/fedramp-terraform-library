# Live proof for release 4.1.0, part A: secret-access-burst-detector with
# enabled = true against a real CloudTrail log group. A single-account trail
# delivers management events to CloudWatch Logs, a fixture role makes the
# denied calls and the secret read, and a queue captures what the detector
# publishes. Nothing here touches account-wide settings, so this stack is
# applied whole.
#
# Apply, run ../probe.py burst, wait, run ../probe.py burst-check, destroy.
# See ../README.md.

terraform {
  required_version = ">= 1.12"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile
  # false: with true the provider also sends the SSO credential call to
  # portal.sso-fips.<region>, which does not exist. The modules under test
  # still default their own Lambdas to FIPS endpoints.
  use_fips_endpoint = false

  default_tags {
    tags = { Purpose = "fedramp-terraform-library-live-proof" }
  }
}

variable "region" {
  description = "Region for the proof stack."
  type        = string
  default     = "us-east-1"
}

variable "profile" {
  description = "AWS CLI profile of the sandbox member account."
  type        = string
  default     = "AdministratorAccess-264524063329"
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  name      = "ftl410"
  partition = data.aws_partition.current.partition
  account   = data.aws_caller_identity.current.account_id
  root_arn  = "arn:${local.partition}:iam::${local.account}:root"
  # Built from the name so the key and bucket policies can name the trail
  # without a dependency cycle.
  trail_arn = "arn:${local.partition}:cloudtrail:${var.region}:${local.account}:trail/${local.name}-trail"
}

# --- Trail to CloudWatch Logs -------------------------------------------------

resource "aws_kms_key" "trail" {
  description             = "Encrypts the ${local.name} proof trail's log files and bucket."
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = local.root_arn }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${local.partition}:cloudtrail:*:${local.account}:trail/*" }
        }
      },
      {
        Sid       = "AllowCloudTrailDescribeKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
    ]
  })
}

resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV_AWS_18: Fixture. Lives for one proof run.
  #checkov:skip=CKV_AWS_144: Fixture. Lives for one proof run.
  #checkov:skip=CKV2_AWS_62: Fixture. Lives for one proof run.
  bucket        = "${local.name}-trail-${local.account}"
  force_destroy = true
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

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire-after-one-day"
    status = "Enabled"
    filter {}

    expiration {
      days = 1
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${local.account}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.trail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudwatch_log_group" "trail" {
  #checkov:skip=CKV_AWS_158: Fixture. Holds one day of sandbox management events for one proof run.
  #checkov:skip=CKV_AWS_338: Fixture. Holds one day of sandbox management events for one proof run.
  name              = "${local.name}-trail-logs"
  retention_in_days = 1
}

resource "aws_iam_role" "trail_to_logs" {
  name = "${local.name}-trail-to-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    }]
  })
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name = "${local.name}-trail-to-logs"
  role = aws_iam_role.trail_to_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:log-stream:${local.account}_CloudTrail_${var.region}*"
    }]
  })
}

# Management events, read and write, are the default selector. Single region:
# us-east-1 also receives the global-service (IAM) events the probe causes.
resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_67: Fixture. Single-region on purpose; the organization trail covers the rest.
  #checkov:skip=CKV_AWS_252: Fixture. Lives for one proof run.
  name                       = "${local.name}-trail"
  s3_bucket_name             = aws_s3_bucket.trail.id
  kms_key_id                 = aws_kms_key.trail.arn
  enable_log_file_validation = true
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_logs.arn

  depends_on = [aws_s3_bucket_policy.trail, aws_iam_role_policy.trail_to_logs]
}

# --- Module under test --------------------------------------------------------

module "burst_detector" {
  source                    = "../../../modules/secret-access-burst-detector"
  name_prefix               = "${local.name}-burst"
  enabled                   = true
  cloudtrail_log_group_name = aws_cloudwatch_log_group.trail.name
  denied_call_threshold     = 5
  ignored_principal_arns    = []
  # Sandbox accounts sit at the 10-execution quota floor.
  reserved_concurrent_executions = -1
}

# --- The principal the detector should report ---------------------------------

resource "aws_secretsmanager_secret" "probe" {
  #checkov:skip=CKV_AWS_149: Fixture. Holds a constant that is not a secret; a CMK would mean giving the actor role kms:Decrypt.
  #checkov:skip=CKV2_AWS_57: Fixture. Lives for one proof run.
  name                    = "${local.name}-probe"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "probe" {
  secret_id     = aws_secretsmanager_secret.probe.id
  secret_string = "not-a-secret"
}

# Assumable from this account only. Its one permission is the read below, so
# every other call it makes is denied.
resource "aws_iam_role" "burst_actor" {
  name = "${local.name}-burst-actor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.root_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "burst_actor" {
  name = "${local.name}-burst-actor"
  role = aws_iam_role.burst_actor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = aws_secretsmanager_secret.probe.arn
    }]
  })
}

# --- Notification capture -----------------------------------------------------

resource "aws_sqs_queue" "capture" {
  #checkov:skip=CKV_AWS_27: SSE-SQS is enough for a queue that holds test notifications for one run.
  name                      = "${local.name}-capture"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 86400
}

resource "aws_sqs_queue_policy" "capture" {
  queue_url = aws_sqs_queue.capture.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.capture.arn
      Condition = { ArnEquals = { "aws:SourceArn" = module.burst_detector.sns_topic_arn } }
    }]
  })
}

resource "aws_sns_topic_subscription" "capture" {
  topic_arn = module.burst_detector.sns_topic_arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.capture.arn

  depends_on = [aws_sqs_queue_policy.capture]
}

# --- What probe.py reads ------------------------------------------------------

output "probe" {
  description = "Names and ARNs ../probe.py needs."
  value = {
    region            = var.region
    profile           = var.profile
    actor_role_arn    = aws_iam_role.burst_actor.arn
    secret_id         = aws_secretsmanager_secret.probe.name
    detector_lambda   = module.burst_detector.lambda_function_arn
    capture_queue_url = aws_sqs_queue.capture.id
    trail_log_group   = aws_cloudwatch_log_group.trail.name
  }
}
