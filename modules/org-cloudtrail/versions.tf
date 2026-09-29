terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # The upper bound tracks the newest provider release tested here;
      # Dependabot raises it. v6 deprecated aws_region's `name` attribute in
      # favor of `region`, but `name` still works through 6.x, so the floor
      # stays at 5.0 for callers who haven't upgraded.
      version = ">= 5.0, < 6.66"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}
