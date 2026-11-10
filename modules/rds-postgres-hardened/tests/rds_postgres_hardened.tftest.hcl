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
  target          = aws_kms_key.rds
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/rds"
  }
}

override_resource {
  target          = aws_security_group.db
  override_during = plan
  values = {
    id = "sg-0aaaaaaaaaaaaaaa1"
  }
}

variables {
  vpc_id             = "vpc-0aaaaaaaaaaaaaaa1"
  vpc_cidr           = "10.0.0.0/16"
  private_subnet_ids = ["subnet-0aaaaaaaaaaaaaaa1", "subnet-0aaaaaaaaaaaaaaa2"]
}

run "instance_is_private_and_encrypted" {
  command = plan

  assert {
    condition     = !aws_db_instance.this.publicly_accessible
    error_message = "The database must not be publicly accessible (SC-7)."
  }

  assert {
    condition     = aws_db_instance.this.storage_encrypted
    error_message = "Storage must be encrypted with the module's CMK (SC-28)."
  }

  assert {
    condition     = aws_db_instance.this.manage_master_user_password && aws_db_instance.this.iam_database_authentication_enabled
    error_message = "The master password must live in Secrets Manager and IAM authentication must be on (IA-5)."
  }
}

run "resilience_and_retention" {
  command = plan

  assert {
    condition     = aws_db_instance.this.multi_az && aws_db_instance.this.deletion_protection && !aws_db_instance.this.skip_final_snapshot
    error_message = "The database must be Multi-AZ, deletion-protected and keep a final snapshot (CP-9, CP-10)."
  }

  assert {
    condition     = aws_db_instance.this.backup_retention_period == 35 && aws_db_instance.this.copy_tags_to_snapshot
    error_message = "Automated backups must be kept 35 days, with tags copied to snapshots (CP-9)."
  }

  assert {
    condition     = !aws_db_instance.this.allow_major_version_upgrade && aws_db_instance.this.auto_minor_version_upgrade
    error_message = "Minor versions must patch automatically; major upgrades must stay a deliberate change (SI-2, CM-3)."
  }
}

run "tls_and_audit_logging" {
  command = plan

  assert {
    condition     = one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "rds.force_ssl"]) == "1"
    error_message = "The parameter group must require TLS (SC-8)."
  }

  assert {
    condition = alltrue([
      for n in ["log_connections", "log_disconnections"] : one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == n]) == "1"
    ]) && one([for p in aws_db_parameter_group.this.parameter : p.value if p.name == "log_statement"]) == "ddl"
    error_message = "Connections, disconnections and DDL must be logged (AU-2, AU-12)."
  }

  assert {
    condition     = toset(aws_db_instance.this.enabled_cloudwatch_logs_exports) == toset(["postgresql", "upgrade"]) && aws_db_instance.this.monitoring_interval == 60 && aws_db_instance.this.performance_insights_enabled
    error_message = "PostgreSQL logs must go to CloudWatch, with enhanced monitoring and Performance Insights on (SI-4)."
  }

  assert {
    condition     = startswith(aws_db_instance.this.engine_version, split("postgres", aws_db_parameter_group.this.family)[1])
    error_message = "The parameter group family must match the engine's major version."
  }
}

run "network_and_role_scoping" {
  command = plan

  assert {
    condition = length(aws_security_group.db.ingress) == 1 && alltrue([
      for r in aws_security_group.db.ingress : r.from_port == 5432 && r.to_port == 5432 && r.protocol == "tcp" && toset(r.cidr_blocks) == toset(["10.0.0.0/16"]) && length(coalesce(r.ipv6_cidr_blocks, [])) == 0 && length(coalesce(r.security_groups, [])) == 0 && length(coalesce(r.prefix_list_ids, [])) == 0 && !coalesce(r.self, false)
    ]) && length(aws_security_group.db.egress) == 0
    error_message = "The database security group may only allow PostgreSQL from the VPC CIDR, with no egress (SC-7)."
  }

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.rds_monitoring_assume.json).Statement).Condition.ArnLike["aws:SourceArn"] == "arn:aws-us-gov:rds:us-gov-west-1:123456789012:db:fedramp-postgres-db"
    error_message = "Only this database's enhanced monitoring may assume the role (confused deputy)."
  }

  assert {
    condition     = aws_kms_key.rds.enable_key_rotation && aws_kms_key.rds.deletion_window_in_days >= 7 && aws_kms_key.rds.deletion_window_in_days <= 30
    error_message = "The RDS CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }
}

run "instance_uses_hardened_companions" {
  command = plan

  assert {
    condition     = aws_db_instance.this.parameter_group_name == aws_db_parameter_group.this.name && aws_db_instance.this.db_subnet_group_name == aws_db_subnet_group.this.name
    error_message = "The instance must use the module's TLS-enforcing parameter group and its private subnet group."
  }

  assert {
    condition     = toset(aws_db_instance.this.vpc_security_group_ids) == toset(["sg-0aaaaaaaaaaaaaaa1"]) && toset(aws_db_subnet_group.this.subnet_ids) == toset(["subnet-0aaaaaaaaaaaaaaa1", "subnet-0aaaaaaaaaaaaaaa2"])
    error_message = "The instance must sit behind the module's security group, in the given private subnets."
  }

  assert {
    condition     = alltrue([for k in [aws_db_instance.this.kms_key_id, aws_db_instance.this.master_user_secret_kms_key_id, aws_db_instance.this.performance_insights_kms_key_id] : k == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/rds"])
    error_message = "Storage, the master secret and Performance Insights must all use the module's CMK (SC-28)."
  }
}
