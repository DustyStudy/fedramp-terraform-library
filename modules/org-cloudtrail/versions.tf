terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Pinned below v6.0 deliberately: v6 renamed several data source
      # attributes used throughout this module (e.g. aws_region's `name`
      # attribute became `region`). If you're already on the v6 provider
      # line, update the attribute references accordingly before removing
      # this ceiling.
      version = ">= 5.0, < 6.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
