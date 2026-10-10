terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # The floor is 6.0 because this module reads aws_region's `region`
      # attribute. See modules/org-cloudtrail/versions.tf for the upper bound.
      version = ">= 6.0, < 6.67"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}
