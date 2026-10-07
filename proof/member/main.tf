# Live proof stack for one sandbox member account. It deploys the
# account-scoped modules with their defaults (sized down where a default
# would cost real money), two deliberately weak fixtures for the auditors to
# find, and a queue that captures every notification the modules send.
#
# Apply, run probe.py, destroy. See docs/PROOF.md for the teardown steps
# that Terraform cannot do on its own.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.66.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region            = var.region
  use_fips_endpoint = true

  default_tags {
    tags = { Purpose = "fedramp-terraform-library-live-proof" }
  }
}

variable "region" {
  description = "Region for the proof stack."
  type        = string
  default     = "us-east-1"
}

variable "external_account_id" {
  description = "An account the auditor should treat as external. The fixture role trusts it and has no permissions."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.external_account_id))
    error_message = "external_account_id must be a 12-digit account ID."
  }
}

locals {
  name = "ftlproof"
  azs  = ["${var.region}a", "${var.region}b"]
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# --- Modules under test -------------------------------------------------------

module "account_baseline" {
  source = "../../modules/account-baseline"
}

module "network_perimeter_vpc" {
  source             = "../../modules/network-perimeter-vpc"
  environment        = local.name
  availability_zones = local.azs
}

data "aws_vpc" "perimeter" {
  id = module.network_perimeter_vpc.vpc_id
}

module "fips_vpc_endpoints" {
  source          = "../../modules/fips-vpc-endpoints"
  environment     = local.name
  vpc_id          = module.network_perimeter_vpc.vpc_id
  vpc_cidr        = data.aws_vpc.perimeter.cidr_block
  subnet_ids      = module.network_perimeter_vpc.application_subnet_ids
  route_table_ids = [data.aws_vpc.perimeter.main_route_table_id]
}

module "ecr_hardened" {
  source          = "../../modules/ecr-hardened"
  repository_name = local.name
}

module "ecs_fargate_hardened" {
  source       = "../../modules/ecs-fargate-hardened"
  cluster_name = local.name
}

module "waf_hardened" {
  source      = "../../modules/waf-hardened"
  environment = local.name
}

module "incident_notifications" {
  source = "../../modules/incident-notifications"
}

# The organization trail delivers to another account, so the CIS metric
# filters get a stand-in log group that probe.py writes one event to.
resource "aws_cloudwatch_log_group" "cloudtrail_stand_in" {
  #checkov:skip=CKV_AWS_158: Holds one synthetic event for the duration of the proof run.
  #checkov:skip=CKV_AWS_338: Holds one synthetic event for the duration of the proof run.
  name              = "${local.name}-cloudtrail-stand-in"
  retention_in_days = 1
}

module "logging_monitoring" {
  source                    = "../../modules/logging-monitoring"
  cloudtrail_log_group_name = aws_cloudwatch_log_group.cloudtrail_stand_in.name
}

module "rds_postgres_hardened" {
  source                = "../../modules/rds-postgres-hardened"
  db_name               = "${local.name}-hardened"
  instance_class        = "db.t3.micro"
  allocated_storage     = 20
  max_allocated_storage = 50
  vpc_id                = module.network_perimeter_vpc.vpc_id
  vpc_cidr              = data.aws_vpc.perimeter.cidr_block
  private_subnet_ids    = module.network_perimeter_vpc.database_subnet_ids
}

module "trust_policy_auditor" {
  source      = "../../modules/trust-policy-auditor"
  name_prefix = "${local.name}-trust-auditor"
}

module "rds_access_auditor" {
  source      = "../../modules/rds-access-auditor"
  name_prefix = "${local.name}-rds-auditor"
}

# --- Fixtures the auditors should flag ---------------------------------------

# Trusts another account with no sts:ExternalId. No policy is attached, so
# assuming it grants nothing.
resource "aws_iam_role" "external_trust_fixture" {
  name = "${local.name}-external-trust-fixture"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${var.external_account_id}:root" }
    }]
  })
}

# Trusts an OIDC provider with no audience or subject condition. The
# provider does not exist, so nothing can assume it. (IAM itself now rejects
# this shape for GitHub's provider, so the fixture uses another host.)
resource "aws_iam_role" "oidc_trust_fixture" {
  name = "${local.name}-oidc-trust-fixture"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/oidc.ftlproof.example" }
    }]
  })
}

resource "random_password" "weak_db" {
  length  = 24
  special = false
}

resource "aws_db_parameter_group" "weak" {
  name        = "${local.name}-weak-pg"
  family      = "postgres16"
  description = "Proof fixture: TLS not enforced"

  parameter {
    name  = "rds.force_ssl"
    value = "0"
  }
}

# Private and encrypted, but with a static master password, no IAM
# authentication and TLS optional: the three settings the auditor reports.
resource "aws_db_instance" "weak_fixture" {
  #checkov:skip=CKV_AWS_161: Fixture. IAM authentication is off so the auditor has something to find.
  #checkov:skip=CKV_AWS_157: Fixture. Single-AZ, lives for one proof run.
  #checkov:skip=CKV_AWS_118: Fixture. Lives for one proof run.
  #checkov:skip=CKV_AWS_129: Fixture. Lives for one proof run.
  #checkov:skip=CKV_AWS_293: Fixture. Must be destroyable without manual steps.
  #checkov:skip=CKV_AWS_353: Fixture. Lives for one proof run.
  #checkov:skip=CKV_AWS_354: Fixture. Lives for one proof run.
  #checkov:skip=CKV_AWS_226: Fixture. Lives for one proof run.
  #checkov:skip=CKV2_AWS_30: Fixture. Lives for one proof run.
  #checkov:skip=CKV2_AWS_60: Fixture. Lives for one proof run.
  #checkov:skip=CKV2_AWS_69: Fixture. TLS is optional so the auditor has something to find.
  identifier             = "${local.name}-weak"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  storage_encrypted      = true
  publicly_accessible    = false
  db_subnet_group_name   = "${local.name}-hardened-subnet-group"
  parameter_group_name   = aws_db_parameter_group.weak.name
  username               = "dbadmin"
  password               = random_password.weak_db.result
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.weak_db.id]

  depends_on = [module.rds_postgres_hardened]
}

resource "aws_security_group" "weak_db" {
  name        = "${local.name}-weak-db"
  description = "Proof fixture: no ingress, no egress"
  vpc_id      = module.network_perimeter_vpc.vpc_id
}

# --- Notification capture -----------------------------------------------------

locals {
  topics = {
    cis      = module.logging_monitoring.cis_alarms_topic_arn
    incident = module.incident_notifications.incident_notification_topic_arn
    trust    = module.trust_policy_auditor.sns_topic_arn
    rds      = module.rds_access_auditor.sns_topic_arn
  }
}

resource "aws_sqs_queue" "capture" {
  #checkov:skip=CKV_AWS_27: SSE-SQS is enough for a queue that holds test notifications for one run.
  name                      = "${local.name}-capture"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 3600
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
      Condition = { ArnEquals = { "aws:SourceArn" = values(local.topics) } }
    }]
  })
}

resource "aws_sns_topic_subscription" "capture" {
  for_each  = local.topics
  topic_arn = each.value
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.capture.arn
}

# --- What probe.py reads ------------------------------------------------------

output "probe" {
  description = "Names and ARNs probe.py needs."
  value = {
    region                = var.region
    vpc_id                = module.network_perimeter_vpc.vpc_id
    ecr_repository        = local.name
    ecs_cluster           = local.name
    web_acl_arn           = module.waf_hardened.web_acl_arn
    backup_vault_arn      = module.account_baseline.backup_vault_arn
    stand_in_log_group    = aws_cloudwatch_log_group.cloudtrail_stand_in.name
    hardened_db           = "${local.name}-hardened"
    weak_db               = aws_db_instance.weak_fixture.identifier
    fixture_role_arn      = aws_iam_role.external_trust_fixture.arn
    oidc_fixture_role_arn = aws_iam_role.oidc_trust_fixture.arn
    trust_auditor_lambda  = module.trust_policy_auditor.lambda_function_arn
    rds_auditor_lambda    = module.rds_access_auditor.lambda_function_arn
    capture_queue_url     = aws_sqs_queue.capture.id
    topics                = local.topics
    fips_endpoint_ids     = module.fips_vpc_endpoints.fips_endpoint_ids
    standard_endpoint_ids = module.fips_vpc_endpoints.standard_endpoint_ids
  }
}
