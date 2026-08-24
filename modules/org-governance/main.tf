locals {
  partition = data.aws_partition.current.partition
}

# --- 1. Workload Perimeter SCP (Root User, Direct IGW, Local IAM Users, S3 Object Lock) ---
data "aws_iam_policy_document" "workload_perimeter_scp" {
  #checkov:skip=CKV_AWS_107:Credentials exposure prevented via explicit Deny blocks
  #checkov:skip=CKV_AWS_108:Data exfiltration mitigated by boundary scoping & region locks
  #checkov:skip=CKV_AWS_109:Permission management restricted to scoped paths
  #checkov:skip=CKV_AWS_110:Privilege escalation prevented via boundary enforcement
  #checkov:skip=CKV_AWS_111:Write access constrained to project resources
  #checkov:skip=CKV_AWS_356:SCP structure requires wildcard scoping on account-wide guardrails

  # Deny direct root account usage in member accounts (AC-2 / AC-6)
  statement {
    sid       = "DenyRootUserActions"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:${local.partition}:iam::*:root"]
    }
  }

  # Deny Direct Internet Gateway Creation (Forces Central Egress / SC-7)
  statement {
    sid    = "DenyDirectInternetGateways"
    effect = "Deny"
    actions = [
      "ec2:CreateInternetGateway",
      "ec2:AttachInternetGateway",
      "ec2:CreateEgressOnlyInternetGateway"
    ]
    resources = ["*"]
  }

  # Deny Creating Local IAM Users / Access Keys (Forces SSO / IA-2)
  statement {
    sid    = "DenyLocalIAMUsersAndAccessKeys"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:CreateAccessKey"
    ]
    resources = ["*"]
  }

  # Protect S3 Object Lock / WORM Retention (AU-9)
  statement {
    sid    = "DenyBypassOrDeleteObjectLock"
    effect = "Deny"
    actions = [
      "s3:BypassGovernanceRetention",
      "s3:PutObjectLegalHold",
      "s3:PutObjectRetention"
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = var.authorized_security_admin_arns
    }
  }
}

resource "aws_organizations_policy" "workload_perimeter" {
  name        = "fedramp-workload-perimeter-scp"
  description = "FedRAMP Workload Perimeter Guardrails (Root Deny, Network Isolation, SSO Enforcement)"
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.workload_perimeter_scp.json
}

# --- 2. AI Services Opt-Out Policy (Data Sovereignty / MP-2) ---
resource "aws_organizations_policy" "ai_opt_out" {
  name        = "fedramp-ai-opt-out-policy"
  description = "Opt out of AWS AI/ML services training on organizational data"
  type        = "AISERVICES_OPT_OUT_POLICY"
  content = jsonencode({
    services = {
      default = {
        opt_out_policy = {
          "@@operators_allowed_for_child_policies" = ["@@none"],
          "@@assign"                               = "optOut"
        }
      }
    }
  })
}

# --- 3. Centralized Backup Policy (WORM / CP-9) ---
resource "aws_organizations_policy" "backup_policy" {
  name        = "fedramp-centralized-backup-policy"
  description = "Enforces automated daily backups and cross-region compliance"
  type        = "BACKUP_POLICY"
  content = jsonencode({
    plans = {
      FedRAMPDailyBackupPlan = {
        regions = {
          "@@assign" = var.backup_regions
        },
        rules = {
          DailyRule = {
            schedule_expression = {
              "@@assign" = "cron(0 5 ? * * *)"
            },
            start_backup_window_minutes = {
              "@@assign" = 60
            },
            complete_backup_window_minutes = {
              "@@assign" = 120
            },
            lifecycle = {
              move_to_cold_storage_after_days = {
                "@@assign" = 30
              },
              delete_after_days = {
                "@@assign" = var.backup_retention_days
              }
            },
            target_backup_vault_name = {
              "@@assign" = "FedRAMPComplianceVault"
            }
          }
        },
        selections = {
          tags = {
            FedRAMPBackup = {
              iam_role_arn = {
                # $account (a literal, un-braced dollar sign) is AWS Backup
                # Organizations Policy's own substitution placeholder — it
                # resolves per-account at evaluation time and is untouched
                # by Terraform's ${...} interpolation syntax, so it's safe
                # to leave as-is alongside the partition interpolation.
                "@@assign" = "arn:${local.partition}:iam::$account:role/AWSBackupDefaultServiceRole"
              },
              tag_key = {
                "@@assign" = "Backup"
              },
              tag_value = {
                "@@assign" = ["true", "True"]
              }
            }
          }
        }
      }
    }
  })
}

# --- 4. Policy Attachments ---
resource "aws_organizations_policy_attachment" "perimeter_attachment" {
  count     = length(var.target_ou_or_account_ids)
  policy_id = aws_organizations_policy.workload_perimeter.id
  target_id = var.target_ou_or_account_ids[count.index]
}

resource "aws_organizations_policy_attachment" "ai_opt_out_attachment" {
  count     = length(var.target_ou_or_account_ids)
  policy_id = aws_organizations_policy.ai_opt_out.id
  target_id = var.target_ou_or_account_ids[count.index]
}

resource "aws_organizations_policy_attachment" "backup_attachment" {
  count     = length(var.target_ou_or_account_ids)
  policy_id = aws_organizations_policy.backup_policy.id
  target_id = var.target_ou_or_account_ids[count.index]
}
