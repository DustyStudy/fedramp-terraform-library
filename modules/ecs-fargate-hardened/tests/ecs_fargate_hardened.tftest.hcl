# Plan-only tests. Dummy credentials plus overridden identity data keep the
# real AWS provider from calling AWS.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
  }
}

override_data {
  target = data.aws_region.current
  values = {
    name = "us-gov-west-1"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

override_resource {
  target          = aws_kms_key.ecs
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/ecs"
  }
}

variables {
  cluster_name = "app"
}

run "cluster_is_hardened" {
  command = plan

  assert {
    condition     = one([for s in aws_ecs_cluster.this.setting : s.value if s.name == "containerInsights"]) == "enabled"
    error_message = "Container Insights must be on (AU-12, SI-4)."
  }

  assert {
    condition     = aws_ecs_cluster.this.configuration[0].execute_command_configuration[0].logging == "OVERRIDE"
    error_message = "ECS Exec sessions must log to the module's log group (AU-2)."
  }

  assert {
    condition     = aws_ecs_cluster.this.configuration[0].execute_command_configuration[0].log_configuration[0].cloud_watch_encryption_enabled
    error_message = "ECS Exec session logs must be encrypted (SC-28)."
  }
}

run "log_group_baseline" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.ecs.retention_in_days >= 365
    error_message = "ECS logs must be kept at least 365 days by default (AU-11)."
  }

  assert {
    condition     = aws_cloudwatch_log_group.ecs.name == "/aws/ecs/app"
    error_message = "The log group must be named after the cluster."
  }
}

run "kms_key_baseline" {
  command = plan

  assert {
    condition     = aws_kms_key.ecs.enable_key_rotation && aws_kms_key.ecs.deletion_window_in_days >= 7 && aws_kms_key.ecs.deletion_window_in_days <= 30
    error_message = "The ECS CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.ecs_kms.json).Statement : s if s.Sid == "AllowCloudWatchLogsEncrypt"]).Principal.Service == "logs.us-gov-west-1.amazonaws.com"
    error_message = "Only the regional CloudWatch Logs service may use the key."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.ecs_kms.json).Statement : s if s.Sid == "AllowCloudWatchLogsEncrypt"]).Condition.ArnLike["kms:EncryptionContext:aws:logs:arn"] == "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:*"
    error_message = "CloudWatch Logs use of the key must be scoped to this account's log groups, built from the current partition."
  }
}

run "consumers_use_module_key" {
  command = plan

  assert {
    condition     = aws_cloudwatch_log_group.ecs.kms_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/ecs" && aws_ecs_cluster.this.configuration[0].execute_command_configuration[0].kms_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/ecs"
    error_message = "The log group and ECS Exec sessions must use the module's CMK (SC-28)."
  }
}
