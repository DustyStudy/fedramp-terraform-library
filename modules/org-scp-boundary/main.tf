data "aws_partition" "current" {}

locals {
  govcloud         = data.aws_partition.current.partition == "aws-us-gov"
  approved_regions = var.approved_regions != null ? var.approved_regions : (local.govcloud ? ["us-gov-west-1", "us-gov-east-1"] : ["us-east-1", "us-west-2"])
}

# A warning, not an error: callers that attach the SCP with no exemptions
# on purpose (nothing deployed in the targets yet) still plan and apply.
check "exempt_principals_set_when_attached" {
  assert {
    condition     = length(var.target_ou_or_account_ids) == 0 || length(var.exempt_principal_arns) > 0
    error_message = "exempt_principal_arns is empty while the SCP is attached to targets. No principal in those accounts, your deployment pipeline included, can set the S3 account public access block, change GuardDuty or Config, or delete a KMS key. Add your deployment and security-admin role ARNs."
  }
}

data "aws_iam_policy_document" "fedramp_boundary_scp" {
  #checkov:skip=CKV_AWS_107:Credentials exposure prevented via explicit Deny blocks
  #checkov:skip=CKV_AWS_108:Data exfiltration mitigated by boundary scoping & region locks
  #checkov:skip=CKV_AWS_109:Permission management restricted to scoped paths
  #checkov:skip=CKV_AWS_110:Privilege escalation prevented via boundary enforcement
  #checkov:skip=CKV_AWS_111:Write access constrained to project resources
  #checkov:skip=CKV_AWS_356:SCP structure requires wildcard scoping on account-wide guardrails

  # 1. Deny Disabling Security and Audit Services
  statement {
    sid    = "DenyDisablingSecurityServices"
    effect = "Deny"
    actions = [
      "cloudtrail:DeleteTrail",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors",
      "config:DeleteConfigRule",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:StopConfigurationRecorder",
      "guardduty:DeleteDetector",
      "guardduty:DisassociateFromMasterAccount",
      "guardduty:DisassociateFromAdministratorAccount",
      "guardduty:DisassociateMembers",
      "guardduty:DeleteMembers",
      "guardduty:StopMonitoringMembers",
      "guardduty:UpdateDetector",
      "securityhub:DeleteHub",
      "securityhub:DisableSecurityHub",
      "securityhub:BatchDisableStandards",
      "securityhub:DisassociateFromAdministratorAccount",
      "securityhub:DisassociateFromMasterAccount",
      "securityhub:DisassociateMembers",
      "securityhub:DeleteMembers",
      "securityhub:DisableImportFindingsForProduct",
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey"
    ]
    resources = ["*"]

    dynamic "condition" {
      for_each = length(var.exempt_principal_arns) > 0 ? [1] : []
      content {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.exempt_principal_arns
      }
    }
  }

  # 2. Deny Leaving Organization or Modifying Account Baseline
  statement {
    sid    = "DenyModifyingAccountBaseline"
    effect = "Deny"
    actions = [
      "organizations:LeaveOrganization",
      "s3:DeleteAccountPublicAccessBlock",
      "s3:PutAccountPublicAccessBlock",
      "ec2:DisableEbsEncryptionByDefault"
    ]
    resources = ["*"]

    dynamic "condition" {
      for_each = length(var.exempt_principal_arns) > 0 ? [1] : []
      content {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.exempt_principal_arns
      }
    }
  }

  # 3. Deny Non-Approved Regions (SC-7)
  # Global services and actions answer from us-east-1 (or the partition's
  # home region) whatever region the caller uses, so they must be exempt or
  # they break whenever approved_regions leaves that region out.
  statement {
    sid    = "DenyUnapprovedRegions"
    effect = "Deny"
    not_actions = [
      "account:*",
      "aws-portal:*",
      "billing:*",
      "budgets:*",
      "ce:*",
      "cloudfront:*",
      "consolidatedbilling:*",
      "cur:*",
      "ec2:DescribeRegions",
      "ecr-public:*",
      "freetier:*",
      "globalaccelerator:*",
      "health:*",
      "iam:*",
      "invoicing:*",
      "organizations:*",
      "payments:*",
      "pricing:*",
      "route53:*",
      "route53domains:*",
      "s3:GetAccountPublicAccessBlock",
      "s3:GetBucketLocation",
      "s3:ListAllMyBuckets",
      "s3:ListMultiRegionAccessPoints",
      "savingsplans:*",
      "shield:*",
      "sts:*",
      "support:*",
      "tax:*",
      "trustedadvisor:*",
      "waf:*"
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = local.approved_regions
    }
  }

  # 4. Require IMDSv2 on new and modified instances (AC-3 / SC-7), opt-in.
  # IMDSv1 answers any unauthenticated GET, which is how SSRF bugs leak an
  # instance role's credentials.
  dynamic "statement" {
    for_each = var.require_imdsv2 ? [1] : []
    content {
      sid       = "DenyLaunchWithoutIMDSv2"
      effect    = "Deny"
      actions   = ["ec2:RunInstances"]
      resources = ["arn:${data.aws_partition.current.partition}:ec2:*:*:instance/*"]
      condition {
        test     = "StringNotEquals"
        variable = "ec2:MetadataHttpTokens"
        values   = ["required"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.require_imdsv2 ? [1] : []
    content {
      sid       = "DenyDowngradeToIMDSv1"
      effect    = "Deny"
      actions   = ["ec2:ModifyInstanceMetadataOptions"]
      resources = ["*"]
      condition {
        test     = "StringNotEquals"
        variable = "ec2:MetadataHttpTokens"
        values   = ["required"]
      }
    }
  }

  # 5. Deny Unencrypted Transport (SC-8 / SC-13)
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*", "sqs:*", "dynamodb:*"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_organizations_policy" "fedramp_boundary" {
  name        = var.policy_name
  description = "FedRAMP Comprehensive Authorization Boundary SCP"
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.fedramp_boundary_scp.json

  lifecycle {
    precondition {
      condition     = length(local.approved_regions) > 0 && alltrue([for r in local.approved_regions : startswith(r, "us-gov-") == local.govcloud])
      error_message = "approved_regions must be non-empty and belong to the provider's partition (${data.aws_partition.current.partition}): only us-gov-* regions in aws-us-gov, and no us-gov-* regions elsewhere. Otherwise the region lock denies every regional action in the targeted accounts."
    }
  }
}

resource "aws_organizations_policy_attachment" "target_attachment" {
  count     = length(var.target_ou_or_account_ids)
  policy_id = aws_organizations_policy.fedramp_boundary.id
  target_id = var.target_ou_or_account_ids[count.index]
}
