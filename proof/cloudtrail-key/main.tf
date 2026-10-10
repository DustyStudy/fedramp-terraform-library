# Live proof of one statement: the org-cloudtrail key policy must let
# CloudWatch Logs encrypt the trail's log group. A member account cannot
# create an organization trail, so this stack is applied with -target and
# creates only the key and the log group:
#
#   terraform apply -target=module.org_cloudtrail.aws_cloudwatch_log_group.trail
#
# CloudWatch Logs refuses to create a log group with a key it cannot use,
# so the apply itself is the first check. ../controls_probe.py then writes
# and reads one event.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.67"
    }
  }
}

provider "aws" {
  region            = var.region
  use_fips_endpoint = true

  default_tags {
    tags = { Purpose = "fedramp-terraform-library-live-proof" }
  }
}

variable "region" {
  description = "Region for the proof stack."
  type        = string
  default     = "us-east-1"
}

data "aws_organizations_organization" "current" {}

module "org_cloudtrail" {
  source          = "../../modules/org-cloudtrail"
  organization_id = data.aws_organizations_organization.current.id
  trail_name      = "ftlproof-trail"
}

output "probe" {
  description = "Names controls_probe.py needs."
  value = {
    region               = var.region
    cloudtrail_log_group = "ftlproof-trail-logs"
  }
}
