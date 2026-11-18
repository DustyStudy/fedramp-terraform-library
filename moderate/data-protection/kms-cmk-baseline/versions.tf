terraform {
  required_version = ">= 1.12"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # See modules/org-cloudtrail/versions.tf for how this range is kept.
      version = ">= 6.0, < 7.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
