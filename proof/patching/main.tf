# Live proof stack for patching and S3 flow logs, in one sandbox member
# account. It deploys ssm-patching-hardened with one Amazon Linux 2023
# instance in the patch group, and moderate/network-boundary/vpc-flow-logs
# on the same VPC.
#
# Apply, run ../controls_probe.py, destroy. See docs/LIVE-PROOF.md.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.67"
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
  description = "Region for the proof stack. Export AWS_REGION to the same value: the flow-log stack configures its own provider from the environment."
  type        = string
  default     = "us-east-1"
}

variable "maintenance_window_cron" {
  description = "Schedule for the patch window. Every 15 minutes, so the probe sees an execution without waiting for Sunday."
  type        = string
  default     = "cron(0/15 * * * ? *)"
}

variable "attach_patch_log_writer" {
  description = "Attach the module's patch-log-writer policy to the instance role. Set false to see Run Command output fail to reach the bucket."
  type        = bool
  default     = true
}

locals {
  name = "ftlpatch"
  azs  = ["${var.region}a", "${var.region}b"]
}

data "aws_partition" "current" {}

# --- Network: private subnets, reached through endpoints only -----------------

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

# --- Modules under test -------------------------------------------------------

module "ssm_patching_hardened" {
  source                  = "../../modules/ssm-patching-hardened"
  environment             = local.name
  maintenance_window_cron = var.maintenance_window_cron
}

module "vpc_flow_logs" {
  source = "../../moderate/network-boundary/vpc-flow-logs"
  vpc_id = module.network_perimeter_vpc.vpc_id
}

# --- One managed node in the patch group --------------------------------------

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${var.region}.s3"
}

resource "aws_iam_role" "node" {
  name = "${local.name}-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "node_patch_log_writer" {
  count      = var.attach_patch_log_writer ? 1 : 0
  role       = aws_iam_role.node.name
  policy_arn = module.ssm_patching_hardened.patch_log_writer_policy_arn
}

resource "aws_iam_instance_profile" "node" {
  name = "${local.name}-node"
  role = aws_iam_role.node.name
}

# No ingress. Egress is TLS to the interface endpoints and to S3 through the
# gateway endpoint, which is where Amazon Linux 2023 keeps its repositories.
resource "aws_security_group" "node" {
  name        = "${local.name}-node"
  description = "Proof node: no ingress, TLS egress to VPC endpoints and S3"
  vpc_id      = module.network_perimeter_vpc.vpc_id

  egress {
    description = "TLS to the interface endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.perimeter.cidr_block]
  }

  egress {
    description     = "TLS to S3 through the gateway endpoint"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.s3.id]
  }
}

resource "aws_instance" "node" {
  ami                    = data.aws_ssm_parameter.al2023.insecure_value
  instance_type          = "t3.micro"
  subnet_id              = module.network_perimeter_vpc.application_subnet_ids[0]
  iam_instance_profile   = aws_iam_instance_profile.node.name
  vpc_security_group_ids = [aws_security_group.node.id]
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name       = "${local.name}-node"
    PatchGroup = "FedRAMPCompliance"
  }

  # The agent registers on first boot, so the endpoints must exist first.
  depends_on = [module.fips_vpc_endpoints, aws_iam_role_policy_attachment.node_ssm]
}

# --- What controls_probe.py reads ---------------------------------------------

output "probe" {
  description = "Names and IDs controls_probe.py needs."
  value = {
    region                     = var.region
    instance_id                = aws_instance.node.id
    patch_baseline_id          = module.ssm_patching_hardened.patch_baseline_id
    maintenance_window_id      = module.ssm_patching_hardened.maintenance_window_id
    maintenance_window_role    = "${local.name}-ssm-mw-execution-role"
    patch_logs_bucket          = split(":::", module.ssm_patching_hardened.patch_logs_bucket_arn)[1]
    writer_policy_attached     = var.attach_patch_log_writer
    flow_log_id                = module.vpc_flow_logs.flow_log_id
    flow_log_bucket            = module.vpc_flow_logs.flow_log_bucket_name
    flow_log_access_log_bucket = module.vpc_flow_logs.flow_log_access_log_bucket_name
  }
}
