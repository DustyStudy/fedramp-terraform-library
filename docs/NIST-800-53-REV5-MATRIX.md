# NIST SP 800-53 Rev 5 Control Mapping Matrix

This document maps the modules in this library to NIST SP 800-53 Rev 5
controls relevant to **FedRAMP Moderate** and **FedRAMP High**. Every cell
here was checked directly against the module code as of this writing —
where a control is only *partially* addressed, or where a module protects
a setting rather than creating it, that distinction is called out
explicitly rather than glossed over. This is a starting point for your
control implementation narrative, not a substitute for your own SSP
language or your 3PAO's assessment.

| Control ID | Control Name | Implemented By | Detail |
| :--- | :--- | :--- | :--- |
| **AC-2** | Account Management | `moderate/iam-access-control`, `modules/account-baseline`, `modules/org-governance` | MFA-enforcement IAM group; account-wide password policy; SCP denies direct root-account API usage in member accounts. |
| **AC-3** | Access Enforcement | `modules/org-scp-boundary`, `modules/fips-vpc-endpoints` | Region-lock and security-guardrail SCPs restrict what member accounts can do; VPC endpoints keep AWS API traffic off the public internet. |
| **AC-4** | Information Flow Enforcement | `modules/org-scp-boundary`, `modules/org-governance` | SCPs deny API calls outside the approved region list and deny direct Internet Gateway creation, forcing traffic through an approved path. |
| **AC-6** | Least Privilege | `moderate/iam-access-control`, `modules/org-scp-boundary` | Permission-boundary policy caps what any attached role/user can do regardless of its own identity policy; SCP closes several IAM privilege-escalation paths. Container workloads (`ecs-fargate-hardened`, `eks-hardened`) do *not* currently enforce non-root execution — that's a gap, not a feature, if you need it. |
| **AU-2** | Event Logging | `modules/org-cloudtrail` | Multi-region organization trail with management + S3 data events. |
| **AU-3** | Content of Audit Records | `modules/org-cloudtrail` | CloudTrail log file validation enabled; CloudWatch Logs integration carries full event detail (identity, source IP, timestamp, parameters). |
| **AU-6** | Audit Record Review | `moderate/logging-monitoring` | 14 CIS/Security Hub CloudWatch alarms (root usage, unauthorized API calls, IAM/network/config changes, etc.) — see that module's README for the full list. |
| **AU-9** | Protection of Audit Information | `modules/org-cloudtrail`, `modules/org-governance` | CloudTrail logs are KMS-encrypted with a dedicated CMK. `org-governance`'s SCP denies bypassing or deleting Object Lock retention settings *if* a bucket has Object Lock configured — it does not itself enable Object Lock on any bucket; that's a separate step you'd add per-bucket. |
| **AU-12** | Audit Record Generation | `modules/config-conformance-pack`, `modules/ecs-fargate-hardened` | AWS Config continuous resource recording; ECS Exec sessions logged to a KMS-encrypted CloudWatch log group. |
| **CM-6** | Configuration Settings | `modules/config-conformance-pack` | FedRAMP Moderate conformance pack (AWS-managed Config rule set) evaluates configuration drift continuously. |
| **CM-7** | Least Functionality | `modules/account-baseline`, `modules/network-perimeter-vpc` | Both modules optionally adopt the default VPC and strip its default security group down to zero ingress/egress rules. |
| **CM-8** | Information System Component Inventory | `modules/config-conformance-pack` | AWS Config tracks all supported resource types plus global resources across the account. |
| **CP-9** | System Backup | `modules/org-governance` | Organization Backup Policy enforces a daily backup schedule with cold-storage transition and a configurable retention period, applied via tag-based resource selection. Note: this is a scheduling/retention policy, not a vault-lock/immutability configuration — add AWS Backup Vault Lock separately if your SSP requires WORM-protected backups. |
| **CP-10** | System Recovery & Reconstitution | `modules/rds-postgres-hardened` | Multi-AZ automated failover; 35-day automated backup retention. |
| **IA-2** | Identification and Authentication | `moderate/iam-access-control` | Enforced-MFA IAM group denies nearly all actions to IAM users without MFA present (governs IAM users only — SSO/Identity Center MFA lives with your IdP). |
| **IA-5** | Authenticator Management | `modules/account-baseline`, `modules/iam-password-policy` | Account password policy (14+ character minimum, 60-day max age, 24-generation reuse prevention). `rds-postgres-hardened`'s master password is stored and rotated through RDS's managed-master-user-password feature (backed by Secrets Manager) rather than a custom rotation Lambda. |
| **IR-4** | Incident Handling | `modules/guardduty-org`, `moderate/incident-response` | GuardDuty findings routed to SNS; a separate aggregation topic collects GuardDuty + Security Hub high-severity findings into one feed. |
| **MP-2** | Media Protection | `modules/account-baseline`, `modules/org-governance` | Account-level and organization-level S3 Public Access Block prevent accidental public exposure of stored data. |
| **RA-5** | Vulnerability Monitoring and Scanning | `modules/ecr-hardened`, `modules/guardduty-org` | ECR scan-on-push for container images; GuardDuty for runtime threat detection (malware protection, S3 data events, Kubernetes audit logs). |
| **SC-7** | Boundary Protection | `modules/org-scp-boundary`, `modules/network-perimeter-vpc`, `modules/fips-vpc-endpoints` | Region-lock SCP; VPC Flow Logs on all traffic; default security group locked to zero rules; VPC endpoints keep AWS API traffic within the VPC. |
| **SC-8** | Transmission Confidentiality and Integrity | `modules/rds-postgres-hardened`, `modules/org-scp-boundary` | `rds.force_ssl` parameter enforced; SCP denies non-TLS S3/SQS/DynamoDB access account-wide. |
| **SC-12** | Cryptographic Key Establishment | every module with a dedicated KMS key | All customer-managed keys in this library have automatic annual rotation enabled (`enable_key_rotation = true` / `EnableKeyRotation: true`). |
| **SC-13** | Cryptographic Protection | `modules/eks-hardened`, `modules/fips-vpc-endpoints` | EKS Kubernetes secrets envelope-encrypted with a dedicated CMK. Only `kms`, `ec2`, and `sts` have genuine FIPS-suffixed VPC endpoint service names as of this writing — see that module's variables.tf for which services do and don't, and why. |
| **SC-28** | Protection of Information at Rest | `modules/account-baseline`, `modules/ecr-hardened`, `modules/rds-postgres-hardened`, `modules/org-cloudtrail` | EBS default encryption; KMS-encrypted ECR repositories, RDS storage, and CloudTrail logs. |
| **SI-4** | Information System Monitoring | `modules/guardduty-org`, `moderate/logging-monitoring` | GuardDuty continuous threat detection; CIS-benchmark CloudWatch alarms for anomalous account activity. |
