locals {
  account_id = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}

# KMS CMK for SSM Patch Logs and Output Encryption (FedRAMP SC-13/AU-9)
data "aws_iam_policy_document" "ssm_kms" {
  #checkov:skip=CKV_AWS_109:KMS root account administrative scoping
  #checkov:skip=CKV_AWS_111:KMS key management write access
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
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
}

resource "aws_kms_key" "ssm" {
  description             = "KMS Key for FedRAMP SSM Patch Manager Logs and Output Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ssm_kms.json
}

# S3 Bucket for Patch Execution Logs with SSE-KMS
resource "aws_s3_bucket" "patch_logs" {
  #checkov:skip=CKV_AWS_18:Access logging target can be configured at centralized log sink
  #checkov:skip=CKV_AWS_144:Cross-region replication managed at account baseline level
  #checkov:skip=CKV_AWS_145:KMS CMK encryption enforced below
  #checkov:skip=CKV_AWS_21:Versioning enabled below
  bucket        = "${var.environment}-fedramp-ssm-patch-logs-${local.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "patch_logs" {
  bucket = aws_s3_bucket.patch_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "patch_logs" {
  bucket = aws_s3_bucket.patch_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.ssm.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "patch_logs" {
  bucket                  = aws_s3_bucket.patch_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FedRAMP Custom Linux Patch Baseline (Auto-approves Critical/Important within 7 days)
resource "aws_ssm_patch_baseline" "amazon_linux" {
  name             = "${var.environment}-fedramp-amazon-linux-baseline"
  description      = "FedRAMP SI-2 Compliant Patch Baseline for Amazon Linux"
  operating_system = "AMAZON_LINUX_2023"

  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "Bugfix"]
    }

    patch_filter {
      key    = "SEVERITY"
      values = ["Critical", "Important"]
    }
  }

  approval_rule {
    approve_after_days = 30
    compliance_level   = "MEDIUM"

    patch_filter {
      key    = "SEVERITY"
      values = ["Medium", "Low"]
    }
  }
}

# IAM Role for Maintenance Window Execution
data "aws_iam_policy_document" "ssm_mw_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm_maintenance_window" {
  name               = "${var.environment}-ssm-mw-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ssm_mw_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm_mw_policy" {
  role       = aws_iam_role.ssm_maintenance_window.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSSMMaintenanceWindowRole"
}

# Maintenance Window (Runs weekly for automated compliance patching)
resource "aws_ssm_maintenance_window" "weekly_patch" {
  name     = "${var.environment}-fedramp-weekly-patch-window"
  schedule = var.maintenance_window_cron
  duration = 3
  cutoff   = 1
}

# Target: Instances tagged with PatchGroup = FedRAMPCompliance
resource "aws_ssm_maintenance_window_target" "target" {
  window_id     = aws_ssm_maintenance_window.weekly_patch.id
  name          = "fedramp-compliant-ec2-targets"
  description   = "Targets all instances tagged for FedRAMP automated patch lifecycle"
  resource_type = "INSTANCE"

  targets {
    key    = "tag:PatchGroup"
    values = ["FedRAMPCompliance"]
  }
}

# Maintenance Window Task: Execute AWS-RunPatchBaseline
resource "aws_ssm_maintenance_window_task" "patch_task" {
  window_id        = aws_ssm_maintenance_window.weekly_patch.id
  task_type        = "RUN_COMMAND"
  task_arn         = "AWS-RunPatchBaseline"
  priority         = 1
  service_role_arn = aws_iam_role.ssm_maintenance_window.arn
  max_concurrency  = "50%"
  max_errors       = "0"

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.target.id]
  }

  task_invocation_parameters {
    run_command_parameters {
      output_s3_bucket     = aws_s3_bucket.patch_logs.id
      output_s3_key_prefix = "patch-outputs/"
      service_role_arn     = aws_iam_role.ssm_maintenance_window.arn
      timeout_seconds      = 3600

      parameter {
        name   = "Operation"
        values = ["Install"]
      }
    }
  }
}
