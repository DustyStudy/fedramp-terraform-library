# The read-only role the stale-account detector assumes, for one member
# account. In a real rollout a StackSet creates this in every account; the
# proof creates it in one, so the others show up in the report as accounts
# that could not be read.

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
  region            = "us-east-1"
  use_fips_endpoint = true

  default_tags {
    tags = { Purpose = "fedramp-terraform-library-live-proof" }
  }
}

variable "detector_role_arn" {
  description = "The stale_account_detector_role_arn output of proof/management."
  type        = string
}

variable "policy_json" {
  description = "The member_role_policy_json output of proof/management."
  type        = string
}

resource "aws_iam_role" "read" {
  name = "ftlproof-stale-read"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.detector_role_arn }
    }]
  })
}

resource "aws_iam_role_policy" "read" {
  name   = "stale-access-read"
  role   = aws_iam_role.read.id
  policy = var.policy_json
}
