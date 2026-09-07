terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }
  }
}

provider "aws" {
  # Credentials for the AWS Organizations *management* account.
  # Do not point this at a member account — org-wide resources
  # (organization trail, GuardDuty/Security Hub auto-enrollment, SCPs)
  # can only be created here.
}
