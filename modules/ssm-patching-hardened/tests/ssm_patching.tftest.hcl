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
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

run "patch_group_is_registered_to_the_module_baseline" {
  command = plan

  assert {
    condition     = aws_ssm_patch_group.fedramp.patch_group == "FedRAMPCompliance"
    error_message = "The patch group the window targets must be registered, or nodes use the AWS default baseline."
  }
}

run "window_role_trust_is_scoped_to_this_account" {
  command = plan

  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.ssm_mw_assume.json).Statement :
      s.Condition.StringEquals["aws:SourceAccount"] == "123456789012" &&
      s.Condition.ArnLike["aws:SourceArn"] == "arn:${data.aws_partition.current.partition}:ssm:*:123456789012:*"
    ])
    error_message = "Only Systems Manager acting for this account may assume the maintenance-window role."
  }
}

# The window role may pass itself to nothing. Handing it to Run Command as
# the notification role made every task fail in the live proof.
run "patch_task_passes_no_role_to_run_command" {
  command = plan

  assert {
    condition     = aws_ssm_maintenance_window_task.patch_task.task_invocation_parameters[0].run_command_parameters[0].service_role_arn == null
    error_message = "run_command_parameters must not set service_role_arn."
  }
}

run "access_logging_is_on_by_default" {
  command = plan

  assert {
    condition     = aws_s3_bucket_logging.patch_logs.target_prefix == "ssm-patch-logs/" && length(aws_s3_bucket.access_logs) == 1
    error_message = "With default inputs the patch-log bucket must log access to a bucket the module creates (AU-2)."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.access_logs[0].rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    error_message = "The access-log bucket must use SSE-S3: S3 cannot deliver access logs to an SSE-KMS bucket."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.access_logs[0].block_public_acls,
      aws_s3_bucket_public_access_block.access_logs[0].block_public_policy,
      aws_s3_bucket_public_access_block.access_logs[0].ignore_public_acls,
      aws_s3_bucket_public_access_block.access_logs[0].restrict_public_buckets,
    ]) && aws_s3_bucket_versioning.access_logs[0].versioning_configuration[0].status == "Enabled"
    error_message = "The access-log bucket must block public access and be versioned."
  }

  assert {
    condition     = length(aws_s3_bucket.access_logs[0].bucket) <= 63
    error_message = "The access-log bucket name must fit S3's 63-character limit."
  }
}

run "patch_task_tolerates_some_failed_nodes_by_default" {
  command = plan

  assert {
    condition     = aws_ssm_maintenance_window_task.patch_task.max_errors == "10%" && aws_ssm_maintenance_window_task.patch_task.max_concurrency == "50%"
    error_message = "Defaults must be max_concurrency 50% and max_errors 10%, so one unhealthy node does not stop the rollout."
  }
}

run "patch_task_concurrency_and_errors_follow_variables" {
  command = plan

  variables {
    max_concurrency = "5"
    max_errors      = "0"
  }

  assert {
    condition     = aws_ssm_maintenance_window_task.patch_task.max_errors == "0" && aws_ssm_maintenance_window_task.patch_task.max_concurrency == "5"
    error_message = "The patch task must use max_concurrency and max_errors."
  }
}

run "access_logging_uses_a_given_bucket" {
  command = plan

  variables {
    access_log_bucket = "central-s3-access-logs"
  }

  assert {
    condition     = aws_s3_bucket_logging.patch_logs.target_bucket == "central-s3-access-logs" && length(aws_s3_bucket.access_logs) == 0 && length(aws_s3_bucket_policy.access_logs) == 0
    error_message = "With access_log_bucket set, access logs go there and no sink bucket is created."
  }
}
