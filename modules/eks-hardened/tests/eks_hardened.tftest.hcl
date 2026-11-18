# Plan-only tests. Dummy credentials plus overridden identity data keep the
# real AWS provider from calling AWS.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
  }
}

override_data {
  target = data.aws_region.current
  values = {
    name = "us-gov-west-1"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

override_resource {
  target          = aws_kms_key.eks
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/eks"
  }
}

variables {
  cluster_name       = "app"
  private_subnet_ids = ["subnet-0aaaaaaaaaaaaaaa1", "subnet-0aaaaaaaaaaaaaaa2"]
}

run "api_endpoint_is_private" {
  command = plan

  assert {
    condition     = aws_eks_cluster.this.vpc_config[0].endpoint_private_access && !aws_eks_cluster.this.vpc_config[0].endpoint_public_access
    error_message = "The Kubernetes API endpoint must be private only (SC-7)."
  }

  assert {
    condition     = toset(aws_eks_cluster.this.vpc_config[0].subnet_ids) == toset(["subnet-0aaaaaaaaaaaaaaa1", "subnet-0aaaaaaaaaaaaaaa2"])
    error_message = "The cluster must use the private subnets it is given."
  }
}

run "control_plane_logging" {
  command = plan

  assert {
    condition = toset(aws_eks_cluster.this.enabled_cluster_log_types) == toset([
      "api", "audit", "authenticator", "controllerManager", "scheduler",
    ])
    error_message = "All five control-plane log types must be on (AU-2, AU-12)."
  }

  assert {
    condition     = aws_cloudwatch_log_group.cluster.name == "/aws/eks/app/cluster" && aws_cloudwatch_log_group.cluster.retention_in_days >= 365
    error_message = "The module must pre-create the cluster's log group with at least 365 days retention (AU-11)."
  }
}

run "secrets_envelope_encryption" {
  command = plan

  assert {
    condition     = one(aws_eks_cluster.this.encryption_config).resources == toset(["secrets"])
    error_message = "Kubernetes secrets must be envelope-encrypted with the module's CMK (SC-28)."
  }

  assert {
    condition     = aws_kms_key.eks.enable_key_rotation && aws_kms_key.eks.deletion_window_in_days >= 7 && aws_kms_key.eks.deletion_window_in_days <= 30
    error_message = "The EKS CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }

  assert {
    condition     = one([for s in jsondecode(data.aws_iam_policy_document.eks_kms.json).Statement : s if s.Sid == "AllowCloudWatchLogsEncrypt"]).Condition.ArnLike["kms:EncryptionContext:aws:logs:arn"] == "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/eks/app/cluster"
    error_message = "CloudWatch Logs use of the key must be scoped to the cluster's own log group."
  }
}

run "cluster_role" {
  command = plan

  assert {
    condition     = aws_iam_role_policy_attachment.cluster_policy.policy_arn == "arn:aws-us-gov:iam::aws:policy/AmazonEKSClusterPolicy"
    error_message = "The managed policy ARN must be built from the current partition."
  }

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.eks_cluster_assume.json).Statement).Principal.Service == "eks.amazonaws.com"
    error_message = "Only the EKS service may assume the cluster role."
  }
}

run "consumers_use_module_key" {
  command = plan

  assert {
    condition     = one(one(aws_eks_cluster.this.encryption_config).provider).key_arn == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/eks" && aws_cloudwatch_log_group.cluster.kms_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/eks"
    error_message = "Secrets envelope encryption and the control-plane log group must use the module's CMK (SC-28)."
  }
}

run "access_config_defaults" {
  command = plan

  assert {
    condition     = one(aws_eks_cluster.this.access_config).authentication_mode == "API" && one(aws_eks_cluster.this.access_config).bootstrap_cluster_creator_admin_permissions
    error_message = "The cluster must default to API authentication with the creator bootstrapped as admin."
  }

  assert {
    condition     = length(aws_eks_access_entry.admin) == 0 && length(aws_eks_access_policy_association.admin) == 0
    error_message = "No access entries may be created unless admin principals are given."
  }
}

run "admin_access_entries" {
  command = plan

  variables {
    cluster_admin_principal_arns = [
      "arn:aws-us-gov:iam::123456789012:role/platform-admin",
      "arn:aws-us-gov:iam::123456789012:role/break-glass",
    ]
  }

  assert {
    condition     = toset(keys(aws_eks_access_entry.admin)) == var.cluster_admin_principal_arns && alltrue([for k, e in aws_eks_access_entry.admin : e.principal_arn == k && e.cluster_name == "app"])
    error_message = "Each admin principal must get its own access entry on this cluster."
  }

  assert {
    condition = length(aws_eks_access_policy_association.admin) == 2 && alltrue([
      for k, a in aws_eks_access_policy_association.admin :
      a.principal_arn == k && a.policy_arn == "arn:aws-us-gov:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy" && one(a.access_scope).type == "cluster"
    ])
    error_message = "Each admin principal must be associated cluster-wide with the partition-correct AmazonEKSClusterAdminPolicy ARN."
  }
}

run "access_entries_rejected_in_config_map_mode" {
  command = plan

  variables {
    authentication_mode          = "CONFIG_MAP"
    cluster_admin_principal_arns = ["arn:aws-us-gov:iam::123456789012:role/platform-admin"]
  }

  expect_failures = [aws_eks_access_entry.admin]
}

run "no_admin_at_all_is_rejected" {
  command = plan

  variables {
    bootstrap_cluster_creator_admin_permissions = false
  }

  expect_failures = [aws_eks_cluster.this]
}

run "standard_support_by_default" {
  command = plan

  assert {
    condition     = one(aws_eks_cluster.this.upgrade_policy).support_type == "STANDARD"
    error_message = "The cluster must default to STANDARD support so it never drifts into extended support billing."
  }

  assert {
    condition     = aws_eks_cluster.this.version == "1.36"
    error_message = "The default Kubernetes version must be the one documented in the README."
  }
}

run "invalid_inputs_are_rejected" {
  command = plan

  variables {
    kubernetes_version  = "v1.36.2"
    authentication_mode = "IAM"
    support_type        = "FREE"
  }

  expect_failures = [var.kubernetes_version, var.authentication_mode, var.support_type]
}
