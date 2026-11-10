# Live proof stack for the two account-scoped modules the first runs left out:
# eks-hardened and config-conformance-pack. It also deploys
# network-perimeter-vpc for the cluster's private subnets. No node group is
# created; the control plane alone shows the module's settings.
#
# Apply, run the checks in docs/LIVE-PROOF.md, destroy the same day: the EKS
# control plane bills by the hour.
#
# The Config recorder needs a principal exempt from the org SCP that denies
# config:PutConfigurationRecorder and config:StopConfigurationRecorder.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.66.1"
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

locals {
  name = "ftlproof"
}

module "network_perimeter_vpc" {
  source             = "../../modules/network-perimeter-vpc"
  environment        = "${local.name}-eks"
  availability_zones = ["${var.region}a", "${var.region}b"]
}

module "eks_hardened" {
  source             = "../../modules/eks-hardened"
  cluster_name       = "${local.name}-eks"
  private_subnet_ids = module.network_perimeter_vpc.application_subnet_ids
}

# One managed rule keeps the evaluation cost to a few cents while still
# proving the recorder, delivery channel and pack deploy together.
module "config_conformance_pack" {
  source                         = "../../modules/config-conformance-pack"
  conformance_pack_name          = "${local.name}-pack"
  conformance_pack_template_body = <<-YAML
    Resources:
      S3BucketPublicReadProhibited:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: s3-bucket-public-read-prohibited
          Source:
            Owner: AWS
            SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED
  YAML
}

output "cluster_arn" {
  value = module.eks_hardened.cluster_arn
}

output "config_bucket_name" {
  value = module.config_conformance_pack.config_bucket_name
}

output "conformance_pack_name" {
  value = module.config_conformance_pack.conformance_pack_name
}
