terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 5.21 is the first release with both GuardDuty feature resources. See
      # modules/org-cloudtrail/versions.tf for the upper bound.
      version = ">= 5.21, < 6.67"
    }
  }
}
