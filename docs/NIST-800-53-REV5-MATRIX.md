# NIST SP 800-53 Rev 5 FedRAMP Control Mapping Matrix

This document maps all infrastructure modules in this library directly to NIST SP 800-53 Rev 5 security controls required for **FedRAMP Moderate** and **FedRAMP High** baselines.

---

| Control ID | Control Name | Implemented By Module | Technical Implementation / Enforcement Detail |
| :--- | :--- | :--- | :--- |
| **AC-2** | Account Management | `moderate/iam-access-control`<br>`modules/org-governance` | Enforces IAM MFA requirement group, blocks interactive root usage in member accounts, and disables inactive local credentials. |
| **AC-3** | Access Enforcement | `modules/org-scp-boundary`<br>`modules/fips-vpc-endpoints` | Service Control Policies restrict member accounts to authorized service operations; VPC endpoints strictly limit API calls to private VPC boundaries. |
| **AC-4** | Information Flow Enforcement | `modules/org-scp-boundary`<br>`modules/org-governance`<br>`modules/fips-vpc-endpoints` | Prohibits non-approved regions (`us-east-1`, `us-west-2`), denies direct Internet Gateways in workload VPCs, and enforces PrivateLink interface endpoints. |
| **AC-6** | Least Privilege | `moderate/iam-access-control`<br>`modules/eks-hardened`<br>`modules/ecs-fargate-hardened` | Developer IAM Permissions Boundaries prevent privilege escalation; container workloads run with scoped IAM execution roles and non-root UID policies. |
| **AU-2** | Event Logging | `modules/org-cloudtrail`<br>`modules/eks-hardened`<br>`modules/rds-postgres-hardened` | Captures management events, multi-region trails, S3 data events, all 5 EKS control plane log types, and PostgreSQL DDL audit logs. |
| **AU-3** | Content of Audit Records | `modules/org-cloudtrail` | CloudTrail log file integrity validation enabled; CloudWatch Logs integration logs user identity, source IP, timestamp, and API call parameters. |
| **AU-9** | Protection of Audit Information | `modules/org-cloudtrail`<br>`modules/config-conformance-pack`<br>`modules/org-governance` | Enforces S3 Object Lock (WORM), Customer-Managed KMS Key (CMK) envelope encryption, and SCP explicit denies on deleting or disabling trails and logs. |
| **AU-12** | Audit Record Generation | `modules/config-conformance-pack`<br>`modules/ecs-fargate-hardened` | AWS Config continuous resource recording and ECS Exec CloudWatch log delivery with KMS CMK encryption. |
| **CM-7** | Least Functionality | `modules/account-baseline`<br>`modules/eks-hardened` | Neutralizes default VPC and strips default security groups; disables public cluster endpoints on EKS. |
| **CM-8** | Information System Component Inventory | `modules/config-conformance-pack` | AWS Config Conformance Pack continuously tracks and evaluates full multi-region resource inventories against FedRAMP Moderate/High baselines. |
| **CP-9** | System Backup | `modules/org-governance`<br>`modules/rds-postgres-hardened` | Organization AWS Backup policy enforces automated daily backups and immutable vault retention; RDS automated backups set to 35-day retention. |
| **CP-10** | System Recovery & Reconstitution | `modules/rds-postgres-hardened`<br>`modules/config-conformance-pack` | Multi-AZ automated failover enabled for databases; versioning and cross-region replication configurations for critical compliance sinks. |
| **IA-2** | Identification and Authentication | `moderate/iam-access-control`<br>`modules/org-governance` | Requires hardware/virtual MFA for IAM console users; denies creation of long-lived local IAM access keys via SCP. |
| **IA-5** | Authenticator Management | `modules/account-baseline`<br>`modules/rds-postgres-hardened` | Enforces strict IAM password policy (14/16+ characters, 60-day expiry, 24-history reuse); automated secret rotation via AWS Secrets Manager. |
| **MP-2** | Media Marking & Handling | `modules/org-governance`<br>`modules/account-baseline` | Account-level and Organization-level S3 Public Access Block prevents unauthorized public exposure of Federal media/data. |
| **RA-5** | Vulnerability Monitoring and Scanning | `modules/ecr-hardened`<br>`modules/guardduty-org` | Continuous container vulnerability scan-on-push for ECR; Amazon GuardDuty organizational malware and runtime threat detection. |
| **SC-7** | Boundary Protection | `modules/org-scp-boundary`<br>`modules/fips-vpc-endpoints`<br>`modules/account-baseline` | Restricts access exclusively to approved US FedRAMP regions, blocks direct IGWs, and restricts all VPC endpoint traffic to private subnets. |
| **SC-8** | Transmission Confidentiality and Integrity | `modules/fips-vpc-endpoints`<br>`modules/rds-postgres-hardened`<br>`modules/org-scp-boundary` | Enforces TLS 1.2+ across all data in transit (`aws:SecureTransport`), FIPS 140-2/3 validated endpoint connections, and `rds.force_ssl = 1`. |
| **SC-12** | Cryptographic Key Establishment | `modules/account-baseline`<br>`modules/ecr-hardened`<br>`modules/eks-hardened`<br>`modules/rds-postgres-hardened` | Customer-Managed KMS Keys (CMKs) provisioned with automated 365-day rotation and strict least-privilege key administrative policies. |
| **SC-13** | Cryptographic Protection | `modules/account-baseline`<br>`modules/fips-vpc-endpoints`<br>`modules/eks-hardened` | FIPS 140-2/3 endpoints configured; KMS envelope encryption enforced for Kubernetes secrets and EBS volumes by default. |
| **SC-28** | Protection of Information at Rest | `modules/account-baseline`<br>`modules/ecr-hardened`<br>`modules/rds-postgres-hardened` | Default EBS encryption enabled; KMS CMK encryption enforced across S3 buckets, ECR container registries, and PostgreSQL storage. |
| **SI-4** | Information System Monitoring | `modules/guardduty-org`<br>`moderate/logging-monitoring` | GuardDuty runtime threat detection, AWS CloudWatch Metric Alarms for root usage, and automated SNS alerting. |
