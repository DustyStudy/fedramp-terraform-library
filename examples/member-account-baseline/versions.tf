terraform {
  required_version = ">= 1.11"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

provider "aws" {
  use_fips_endpoint = var.use_fips_endpoint
  # Credentials for a workload/member account. Apply this root once per
  # member account — it is not org-wide.
}
