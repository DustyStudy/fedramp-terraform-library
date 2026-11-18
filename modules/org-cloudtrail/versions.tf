terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # One range for every module and root in this repo. CI runs the test
      # suites at both ends: the floors (Terraform 1.11.0, provider 6.0.0)
      # and the newest release. No patch-level ceiling: a library must not
      # block callers from taking provider security fixes. Only the root
      # stacks commit a lock file, and Dependabot moves those.
      version = ">= 6.0, < 7.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}
