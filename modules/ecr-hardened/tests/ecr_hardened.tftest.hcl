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
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

variables {
  repository_name = "app"
}

run "repository_is_hardened" {
  command = plan

  assert {
    condition     = aws_ecr_repository.this.image_tag_mutability == "IMMUTABLE"
    error_message = "Image tags must be immutable so a pushed tag cannot be replaced (CM-14, SI-7)."
  }

  assert {
    condition     = aws_ecr_repository.this.image_scanning_configuration[0].scan_on_push
    error_message = "Images must be scanned on push (RA-5)."
  }

  assert {
    condition     = aws_ecr_repository.this.encryption_configuration[0].encryption_type == "KMS"
    error_message = "The repository must be encrypted with KMS, not AES256 (SC-28)."
  }
}

run "kms_key_baseline" {
  command = plan

  assert {
    condition     = aws_kms_key.ecr.enable_key_rotation
    error_message = "The ECR CMK must rotate (SC-12)."
  }

  assert {
    condition     = aws_kms_key.ecr.deletion_window_in_days >= 7 && aws_kms_key.ecr.deletion_window_in_days <= 30
    error_message = "The CMK deletion window must be 7 to 30 days."
  }

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.ecr_kms.json).Statement).Principal.AWS == "arn:aws-us-gov:iam::123456789012:root"
    error_message = "The key policy must build the root ARN from the current partition, not a hardcoded arn:aws."
  }
}

run "lifecycle_policy_rules" {
  command = plan

  assert {
    condition     = length(jsondecode(aws_ecr_lifecycle_policy.this.policy).rules) == 4
    error_message = "The lifecycle policy must have one untagged rule plus one rule per retained prefix."
  }

  assert {
    condition     = alltrue([for r in jsondecode(aws_ecr_lifecycle_policy.this.policy).rules : length(try(r.selection.tagPrefixList, [])) <= 1])
    error_message = "Each tagged rule must list a single prefix; a multi-prefix list only matches images carrying every prefix."
  }

  assert {
    condition     = length(distinct([for r in jsondecode(aws_ecr_lifecycle_policy.this.policy).rules : r.rulePriority])) == 4
    error_message = "Lifecycle rule priorities must be unique."
  }

  assert {
    condition = length([
      for r in jsondecode(aws_ecr_lifecycle_policy.this.policy).rules : r
      if r.selection.tagStatus == "untagged" && r.selection.countType == "sinceImagePushed" && r.selection.countNumber == 14 && r.action.type == "expire"
    ]) == 1
    error_message = "Untagged images must expire after 14 days."
  }

  assert {
    condition = toset(flatten([
      for r in jsondecode(aws_ecr_lifecycle_policy.this.policy).rules : r.selection.tagPrefixList
      if r.selection.tagStatus == "tagged" && r.selection.countType == "imageCountMoreThan" && r.selection.countNumber == 30 && r.action.type == "expire"
    ])) == toset(["v", "prod", "release"])
    error_message = "The last 30 images tagged v*, prod* and release* must each be retained."
  }
}

override_resource {
  target          = aws_kms_key.ecr
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/ecr"
  }
}

run "repository_uses_module_key" {
  command = plan

  assert {
    condition     = aws_ecr_repository.this.encryption_configuration[0].kms_key == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/ecr"
    error_message = "The repository must be encrypted with the module's CMK (SC-28)."
  }
}
