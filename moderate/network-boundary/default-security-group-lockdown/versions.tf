terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # See modules/org-cloudtrail/versions.tf for how this range is kept.
      version = ">= 6.0, < 7.0"
    }
  }
}
