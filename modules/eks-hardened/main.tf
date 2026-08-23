locals {
  account_id = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}

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
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
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
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# Hardened EKS Cluster Resource
resource "aws_eks_cluster" "this" {
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

  depends_on = [aws_iam_role_policy_attachment.cluster_policy]
}
