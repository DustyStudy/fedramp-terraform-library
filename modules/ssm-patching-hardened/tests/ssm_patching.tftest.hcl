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
