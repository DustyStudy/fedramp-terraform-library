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
  target          = aws_kms_key.flow_logs
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/flow"
  }
}

override_resource {
  target          = aws_cloudwatch_log_group.flow_logs
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/vpc-flow-logs/fedramp"
  }
}

override_resource {
  target          = aws_iam_role.flow_logs
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:iam::123456789012:role/fedramp-vpc-flow-logs-role"
  }
}

override_resource {
  target          = aws_vpc.this
  override_during = plan
  values = {
    id = "vpc-0aaaaaaaaaaaaaaa1"
  }
}

variables {
  availability_zones = ["us-gov-west-1a", "us-gov-west-1b"]
}

run "flow_logs_capture_all_traffic" {
  command = plan

  assert {
    condition     = aws_flow_log.this.traffic_type == "ALL" && aws_flow_log.this.max_aggregation_interval == 60
    error_message = "VPC flow logs must capture accepted and rejected traffic at one-minute aggregation (AU-12, SI-4)."
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow_logs.retention_in_days >= 365
    error_message = "Flow logs must be kept at least 365 days by default (AU-11)."
  }
}

run "default_security_group_is_closed" {
  command = plan

  assert {
    condition     = length(aws_default_security_group.default.ingress) == 0 && length(aws_default_security_group.default.egress) == 0
    error_message = "The default security group must have no rules (SC-7, CIS 5.4)."
  }
}

run "subnets_do_not_assign_public_ips" {
  command = plan

  assert {
    condition     = alltrue([for s in concat(aws_subnet.public, aws_subnet.application, aws_subnet.database) : !s.map_public_ip_on_launch])
    error_message = "No subnet may assign public IPs on launch (SC-7)."
  }

  assert {
    condition     = length(aws_subnet.public) == 2 && length(aws_subnet.application) == 2 && length(aws_subnet.database) == 2
    error_message = "The VPC must get one subnet per tier per CIDR given."
  }

  assert {
    condition     = [for s in aws_subnet.database : s.availability_zone] == ["us-gov-west-1a", "us-gov-west-1b"]
    error_message = "Subnets must be spread across the given availability zones."
  }
}

run "flow_logs_role_is_scoped" {
  command = plan

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.flow_logs_assume.json).Statement).Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "Only this account's flow logs may assume the role (confused deputy)."
  }

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.flow_logs_assume.json).Statement).Condition.ArnLike["aws:SourceArn"] == "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:vpc-flow-log/*"
    error_message = "The role's source ARN condition must be built from the current partition and region."
  }

  assert {
    condition     = aws_kms_key.flow_logs.enable_key_rotation && aws_kms_key.flow_logs.deletion_window_in_days >= 7 && aws_kms_key.flow_logs.deletion_window_in_days <= 30
    error_message = "The flow log CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }
}

run "flow_log_is_wired_up" {
  command = plan

  assert {
    condition     = aws_flow_log.this.vpc_id == "vpc-0aaaaaaaaaaaaaaa1" && aws_flow_log.this.log_destination == "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/vpc-flow-logs/fedramp" && aws_flow_log.this.iam_role_arn == "arn:aws-us-gov:iam::123456789012:role/fedramp-vpc-flow-logs-role"
    error_message = "The flow log must cover the module's VPC and write to its log group with its role."
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow_logs.kms_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/flow" && aws_default_security_group.default.vpc_id == "vpc-0aaaaaaaaaaaaaaa1"
    error_message = "Flow logs must use the module's CMK, and the closed default security group must be the module VPC's."
  }
}
