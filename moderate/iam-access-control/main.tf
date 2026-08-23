# Account-level IAM access control baseline: IAM Access Analyzer (external
# and unused access), a permission boundary for human/developer roles,
# enforced-MFA policy for IAM users, and root account usage alerting.
#
# Control mapping:
#   Rev5 (Moderate/High): AC-2, AC-2(3), AC-3, AC-6, AC-6(1), AC-6(5),
#     IA-2(1), IA-5(1)
#   FedRAMP 20x: KSI-IAM-01 (strong authentication), KSI-IAM-02 (credential
#     lifecycle), KSI-IAM-03 (least privilege / unused access review)

# --- IAM Access Analyzer: external + unused access ---

resource "aws_accessanalyzer_analyzer" "external_access" {
  analyzer_name = "external-access-${data.aws_caller_identity.current.account_id}"
  type          = var.analyzer_type
}

resource "aws_accessanalyzer_analyzer" "unused_access" {
  analyzer_name = "unused-access-${data.aws_caller_identity.current.account_id}"
  type          = var.analyzer_type

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age
    }
  }
}

# --- Permission boundary for human/developer IAM roles (AC-6, AC-6(1)) ---
# Attach this boundary to any role or user your break-glass/dev tooling
# creates, so even a misconfigured trust policy can't grant more than this
# ceiling allows. It does not grant permissions itself — it caps them.

data "aws_iam_policy_document" "developer_permission_boundary" {
  statement {
    sid    = "AllowMostActionsWithinBoundary"
    effect = "Allow"
    not_actions = [
      "iam:*",
      "organizations:*",
      "account:*",
      "ce:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowLimitedIAMReadOnly"
    effect = "Allow"
    actions = [
      "iam:Get*",
      "iam:List*",
      "iam:GenerateCredentialReport",
      "iam:GenerateServiceLastAccessedDetails",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyBoundaryPolicyModification"
    effect = "Deny"
    actions = [
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/developer-permission-boundary"]
  }

  statement {
    sid    = "DenyRemovingOwnBoundary"
    effect = "Deny"
    actions = [
      "iam:DeleteUserPermissionsBoundary",
      "iam:DeleteRolePermissionsBoundary",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyPrivilegeEscalationViaIAM"
    effect = "Deny"
    actions = [
      # Direct grant paths
      "iam:CreateUser",
      "iam:CreateRole",
      "iam:AttachUserPolicy",
      "iam:AttachRolePolicy",
      "iam:AttachGroupPolicy",
      "iam:PutUserPolicy",
      "iam:PutRolePolicy",
      "iam:PutGroupPolicy",
      "iam:AddUserToGroup",
      # Policy-version manipulation
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      # Trust-policy manipulation
      "iam:UpdateAssumeRolePolicy",
      # Credential creation for other principals
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:UpdateLoginProfile",
    ]
    resources = ["*"]
    # Note: this list covers IAM-only escalation paths. It does NOT cover
    # iam:PassRole combined with a compute service (Lambda, EC2,
    # CloudFormation, etc.) to run code as a more-privileged role — that
    # requires either a resource-scoped PassRole condition per role, or an
    # SCP restricting which roles can be passed to which services. Treat
    # this boundary as one layer, not the only layer.
  }
}

resource "aws_iam_policy" "developer_permission_boundary" {
  #checkov:skip=CKV_AWS_107:Intentional — this is a permission BOUNDARY (a ceiling), not a grant. It's meant to be broad; the actual least-privilege grant lives in whatever identity policy the boundary is attached to.
  #checkov:skip=CKV_AWS_108:Same as CKV_AWS_107 — boundary is a ceiling, not a grant. Data exfiltration risk is governed by the attached identity policy, which this boundary can only narrow, never widen.
  #checkov:skip=CKV_AWS_109:Same as CKV_AWS_107 — this is the boundary's intended shape.
  #checkov:skip=CKV_AWS_110:The DenyPrivilegeEscalationViaIAM statement above specifically closes IAM-based escalation paths; the broad allow is what a boundary is supposed to look like.
  #checkov:skip=CKV_AWS_111:Same as CKV_AWS_107 — boundary is a ceiling, not a grant.
  name        = "developer-permission-boundary"
  description = "Permission boundary ceiling for human/developer roles. Attach via permissions_boundary on role/user creation."
  policy      = data.aws_iam_policy_document.developer_permission_boundary.json
}

# --- Enforced MFA for IAM users (IA-2(1), AC-7) ---
# Users in this group are denied nearly all actions unless authenticated
# with MFA. Add IAM users who need console/API access here.

data "aws_iam_policy_document" "require_mfa" {
  statement {
    sid       = "AllowViewAccountInfo"
    effect    = "Allow"
    actions   = ["iam:GetAccountPasswordPolicy", "iam:GetAccountSummary", "iam:ListVirtualMFADevices"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowManageOwnMFA"
    effect = "Allow"
    actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:DeactivateMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:ListMFADevices",
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/$${aws:username}",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}",
    ]
  }

  statement {
    sid       = "AllowChangeOwnPassword"
    effect    = "Allow"
    actions   = ["iam:ChangePassword", "iam:GetUser"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}"]
  }

  statement {
    sid    = "DenyAllExceptListedUnlessMFAd"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "iam:ChangePassword",
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "sts:GetSessionToken",
    ]
    resources = ["*"]

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_group" "require_mfa" {
  name = "require-mfa"
}

resource "aws_iam_group_policy" "require_mfa" {
  name   = "deny-all-except-mfa-setup-without-mfa"
  group  = aws_iam_group.require_mfa.name
  policy = data.aws_iam_policy_document.require_mfa.json
}

# --- Root account usage alerting (AC-6(5), AU-6) ---

resource "aws_sns_topic" "root_usage_alerts" {
  name              = var.root_usage_alert_topic_name
  kms_master_key_id = "alias/aws/sns"
}

data "aws_iam_policy_document" "root_usage_alerts_topic" {
  statement {
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.root_usage_alerts.arn]
  }
}

resource "aws_sns_topic_policy" "root_usage_alerts" {
  arn    = aws_sns_topic.root_usage_alerts.arn
  policy = data.aws_iam_policy_document.root_usage_alerts_topic.json
}

resource "aws_cloudwatch_event_rule" "root_usage" {
  name        = "root-account-usage"
  description = "Alerts whenever the root account is used for any action. Requires the org/account CloudTrail trail to be logging management events (see modules/org-cloudtrail)."

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_usage" {
  rule = aws_cloudwatch_event_rule.root_usage.name
  arn  = aws_sns_topic.root_usage_alerts.arn
}
