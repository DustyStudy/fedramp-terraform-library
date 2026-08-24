terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # See modules/org-cloudtrail/versions.tf for why this is pinned
      # below v6.0 (data source attribute renames).
      version = ">= 5.0, < 6.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}
