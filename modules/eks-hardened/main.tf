locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# KMS Key for EKS Secrets Envelope Encryption (FedRAMP SC-13/SC-28)
#
# Note: unlike CloudWatch Logs (which explicitly requires a key-policy
# statement for the logs service principal), AWS's EKS documentation does
# not clearly state that same-account secrets encryption needs an explicit
# key-policy statement for the cluster role or eks.amazonaws.com — the
# grant is typically established via the creating principal's own KMS
# permissions at cluster-creation time. If cluster creation fails with a
# KMS access error, that's the first thing to check: either add an
# explicit statement here for aws_iam_role.cluster.arn, or confirm the
# principal running `terraform apply` has kms:CreateGrant on this key.
data "aws_iam_policy_document" "eks_kms" {
  #checkov:skip=CKV_AWS_109:KMS root account scoping
  #checkov:skip=CKV_AWS_111:KMS key management write access
  #checkov:skip=CKV_AWS_356:KMS key policy wildcard scoping
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # CloudWatch Logs encrypts the control-plane log group as the logs
  # service, not as the IAM principal that created it.
  statement {
    sid    = "AllowCloudWatchLogsEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/eks/${var.cluster_name}/cluster"]
    }
  }
}

resource "aws_kms_key" "eks" {
  description             = "KMS Key for EKS Kubernetes Secrets Envelope Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.eks_kms.json
}

# EKS Cluster IAM Role
data "aws_iam_policy_document" "eks_cluster_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.cluster_name}-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_assume.json
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

# Control-plane log group. If this isn't created first, EKS auto-creates
# it with no encryption and no retention limit (AU-9 / AU-11 / SC-28).
resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks.arn
}

# Hardened EKS Cluster Resource
resource "aws_eks_cluster" "this" {
  #checkov:skip=CKV_AWS_339:Checkov's hardcoded version list stops at 1.35; 1.36 and 1.37 are in EKS standard support. Remove once Checkov's list includes them.
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  # All 5 Control Plane Log Streams Enabled (FedRAMP AU-2/AU-12)
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false # Disable public API endpoint (SC-7)
    public_access_cidrs     = []
  }

  # Envelope Encryption for Kubernetes Secrets
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  # Access entries (AC-2/AC-3): cluster access lives in the EKS API, not in
  # the aws-auth ConfigMap that only the creating principal can reach.
  access_config {
    authentication_mode                         = var.authentication_mode
    bootstrap_cluster_creator_admin_permissions = var.bootstrap_cluster_creator_admin_permissions
  }

  # Without this EKS defaults to EXTENDED and bills extended support once
  # the version leaves standard support.
  upgrade_policy {
    support_type = var.support_type
  }

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_cloudwatch_log_group.cluster,
  ]

  lifecycle {
    # Create-only and ForceNew in the provider: a mismatch with the state of
    # an existing cluster must never plan a cluster replacement.
    ignore_changes = [access_config[0].bootstrap_cluster_creator_admin_permissions]

    precondition {
      condition     = var.bootstrap_cluster_creator_admin_permissions || length(var.cluster_admin_principal_arns) > 0
      error_message = "Nobody could administer the cluster: keep bootstrap_cluster_creator_admin_permissions = true or set cluster_admin_principal_arns."
    }
  }
}

# Cluster admins that survive the creating (CI) role being rotated or deleted.
resource "aws_eks_access_entry" "admin" {
  for_each = var.cluster_admin_principal_arns

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value

  lifecycle {
    precondition {
      condition     = var.authentication_mode != "CONFIG_MAP"
      error_message = "cluster_admin_principal_arns needs authentication_mode API or API_AND_CONFIG_MAP; CONFIG_MAP clusters do not support access entries."
    }
  }
}

resource "aws_eks_access_policy_association" "admin" {
  for_each = aws_eks_access_entry.admin

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  policy_arn    = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}
