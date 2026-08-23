locals {
  account_id = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}

# Customer-Managed KMS Key for RDS Storage & Performance Insights
data "aws_iam_policy_document" "rds_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
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

resource "aws_kms_key" "rds" {
  description             = "Dedicated KMS CMK for FedRAMP RDS Database Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.rds_kms.json
}

# DB Subnet Group
resource "aws_db_subnet_group" "this" {
  name        = "${var.db_name}-subnet-group"
  description = "Subnet group for private isolated FedRAMP database tier"
  subnet_ids  = var.private_subnet_ids
}

# Parameter Group Enforcing TLS and Audit Logging
resource "aws_db_parameter_group" "this" {
  name        = "${var.db_name}-pg"
  family      = "postgres16"
  description = "FedRAMP compliant PostgreSQL parameter group enforcing TLS and query logging"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }
}

# Security Group for Database Ingress (Restricted to VPC CIDR, Zero Outbound Egress)
resource "aws_security_group" "db" {
  #checkov:skip=CKV_AWS_23:Database is a backend sink and does not require outbound internet access
  name        = "${var.db_name}-sg"
  description = "Restricted ingress for FedRAMP RDS instance"
  vpc_id      = var.vpc_id

  ingress {
    description = "PostgreSQL TLS port from VPC CIDR"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress = []

  tags = {
    Name = "${var.db_name}-sg"
  }
}

# IAM Role for Enhanced Monitoring
data "aws_iam_policy_document" "rds_monitoring_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${var.db_name}-monitoring-role"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_assume.json
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# Hardened PostgreSQL RDS Instance
resource "aws_db_instance" "this" {
  identifier                            = var.db_name
  engine                                = "postgres"
  engine_version                        = "16.3"
  instance_class                        = var.instance_class
  allocated_storage                     = var.allocated_storage
  max_allocated_storage                 = var.max_allocated_storage
  storage_type                          = "gp3"
  storage_encrypted                     = true
  kms_key_id                            = aws_kms_key.rds.arn
  multi_az                              = true
  publicly_accessible                   = false
  db_subnet_group_name                  = aws_db_subnet_group.this.name
  vpc_security_group_ids                = [aws_security_group.db.id]
  parameter_group_name                  = aws_db_parameter_group.this.name
  username                              = var.admin_username
  manage_master_user_password           = true
  master_user_secret_kms_key_id         = aws_kms_key.rds.arn
  iam_database_authentication_enabled   = true
  auto_minor_version_upgrade            = true
  allow_major_version_upgrade           = false
  deletion_protection                   = true
  copy_tags_to_snapshot                 = true
  backup_retention_period               = 35
  monitoring_interval                   = 60
  monitoring_role_arn                   = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  performance_insights_retention_period = 731
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  skip_final_snapshot                   = false
  final_snapshot_identifier             = "${var.db_name}-final-snapshot"
}
