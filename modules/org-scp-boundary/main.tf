data "aws_partition" "current" {}

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
      values   = var.approved_regions
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
}

resource "aws_organizations_policy_attachment" "target_attachment" {
  count     = length(var.target_ou_or_account_ids)
  policy_id = aws_organizations_policy.fedramp_boundary.id
  target_id = var.target_ou_or_account_ids[count.index]
}
