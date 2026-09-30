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
  use_fips_endpoint = var.use_fips_endpoint
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
