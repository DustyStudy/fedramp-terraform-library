locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# KMS CMK for VPC Flow Logs
data "aws_iam_policy_document" "flow_logs_kms" {
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

  # Required: CloudWatch Logs makes its own encrypt/decrypt calls as the
  # logs service (separate from whichever IAM role publishes flow log
  # records via logs:PutLogEvents). Without this statement, the log group
  # can't be encrypted with this CMK at all.
  statement {
    sid    = "AllowCloudWatchLogsEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "flow_logs" {
  description             = "KMS Key for VPC Flow Logs CloudWatch Log Group"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.flow_logs_kms.json
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc-flow-logs/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.flow_logs.arn
}

# IAM Role for Flow Logs Publishing
data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.environment}-vpc-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
      }
    ]
  })
}

# 3-Tier Hardened VPC
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.environment}-perimeter-vpc"
  }
}

# Default Security Group Neutralization
resource "aws_default_security_group" "default" {
  vpc_id  = aws_vpc.this.id
  ingress = []
  egress  = []
}

# Flow Logs Enforced for ALL Traffic (AU-12)
resource "aws_flow_log" "this" {
  iam_role_arn             = aws_iam_role.flow_logs.arn
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type             = "ALL"
  max_aggregation_interval = 60
  vpc_id                   = aws_vpc.this.id
}

# Subnet Tiers across 2 AZs
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-public-tier-${count.index + 1}"
  }
}

resource "aws_subnet" "application" {
  count             = length(var.app_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.app_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "${var.environment}-app-tier-${count.index + 1}"
  }
}

resource "aws_subnet" "database" {
  count             = length(var.db_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.db_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "${var.environment}-db-isolated-tier-${count.index + 1}"
  }
}
