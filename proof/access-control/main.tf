# Live proof stack for iam-access-control. Apply it where no service control
# policy denies access-analyzer:DeleteAnalyzer, or the analyzers cannot be
# destroyed afterwards: in this organization that is the management account.
#
# Apply, run ../controls_probe.py, destroy. See docs/LIVE-PROOF.md.

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

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

module "iam_access_control" {
  source = "../../modules/iam-access-control"
}

# A role capped by the developer permissions boundary. Its identity policy
# is read-only access to everything, so whatever the probe is refused is
# refused by the boundary. Only principals of this account can assume it.
resource "aws_iam_role" "boundary_fixture" {
  name                 = "ftlproof-boundary-fixture"
  permissions_boundary = module.iam_access_control.permission_boundary_arn
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "boundary_fixture" {
  role       = aws_iam_role.boundary_fixture.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/ReadOnlyAccess"
}

output "probe" {
  description = "Names and ARNs controls_probe.py needs."
  value = {
    region                   = var.region
    external_access_analyzer = module.iam_access_control.external_access_analyzer_arn
    unused_access_analyzer   = module.iam_access_control.unused_access_analyzer_arn
    boundary_fixture_role    = aws_iam_role.boundary_fixture.arn
  }
}
