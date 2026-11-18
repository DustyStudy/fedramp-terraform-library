# State fixture for moved.tftest.hcl: the root-level key that
# high/account-baseline created up to library 3.0.0.
terraform {
  required_version = ">= 1.11"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

resource "aws_kms_key" "ebs" {
  #checkov:skip=CKV2_AWS_64:State fixture for a mocked test, never deployed; the real key and its policy are in modules/account-baseline
  enable_key_rotation = true
}

output "ebs_kms_key_arn" {
  value = aws_kms_key.ebs.arn
}
