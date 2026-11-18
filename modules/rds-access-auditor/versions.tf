terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # The floor is 6.0 because this module reads aws_region's `region`
      # attribute. See modules/org-cloudtrail/versions.tf for how this range is kept.
      version = ">= 6.0, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}
