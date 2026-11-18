# rds-postgres-hardened

A Multi-AZ PostgreSQL RDS instance with enforced TLS (`rds.force_ssl`),
KMS storage encryption, AWS-managed master password (Secrets Manager,
not a Terraform-state secret), IAM database authentication, and enhanced
monitoring.

## Usage

```hcl
module "rds_postgres_hardened" {
  source              = "../../modules/rds-postgres-hardened"
  db_name             = "my-app-db"
  instance_class      = "db.r6g.large"
  vpc_id              = var.vpc_id
  vpc_cidr            = var.vpc_cidr
  private_subnet_ids  = var.database_subnet_ids
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| CP-9, CP-10, SC-8, SC-12, SC-28, IA-5 | KSI-SVC-SIN, KSI-SVC-VCM |

## Notes

- **The master password is never in Terraform state.** `manage_master_user_password
  = true` delegates credential generation and rotation to RDS/Secrets
  Manager; retrieve it via `master_user_secret_arn` (this module's
  output) at connection time, don't expect a `password` attribute.
- The security group has ingress restricted to `var.vpc_cidr` on 5432 and
  zero outbound egress — this is a backend data-tier sink by design.
  Application layers connect in; the database doesn't need to call out.
- `deletion_protection = true` and `skip_final_snapshot = false` are both
  hardcoded, not variables — deleting this instance via `terraform
  destroy` will fail until you deliberately disable deletion protection,
  and a final snapshot is always taken. That's intentional for a
  FedRAMP-track database; adjust in your root config if this module is
  reused for non-production/ephemeral databases.
- `engine_version` defaults to the major version only (`"16"`). With
  `auto_minor_version_upgrade = true`, RDS picks the current minor version
  and later minor upgrades do not show as drift. Setting a full version
  such as `"16.9"` only chooses the starting minor version. The parameter
  group family (`postgres16`) is derived from the major version.
- Changing the major version of an existing database is not a one-variable
  change: `allow_major_version_upgrade` is hardcoded to `false` and the
  parameter group keeps one fixed name, so plan a major upgrade
  separately.
- The module creates the `/aws/rds/instance/<db_name>/postgresql` and
  `/upgrade` log groups itself, encrypted with the module's CMK and kept
  for `log_retention_days` (default 365). If RDS already created them for
  an existing database, import them before applying:

  ```hcl
  import {
    to = module.rds_postgres_hardened.aws_cloudwatch_log_group.rds["postgresql"]
    id = "/aws/rds/instance/my-app-db/postgresql"
  }

  import {
    to = module.rds_postgres_hardened.aws_cloudwatch_log_group.rds["upgrade"]
    id = "/aws/rds/instance/my-app-db/upgrade"
  }
  ```

  RDS creates a log group only when it first writes to it, so the
  `upgrade` group may not exist yet; leave out its `import` block in that
  case.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| private_subnet_ids | List of private isolated subnet IDs across at least 2 Availability Zones | `list(string)` | n/a | yes |
| vpc_cidr | VPC CIDR allowed to communicate with the database | `string` | n/a | yes |
| vpc_id | VPC ID where the database resides | `string` | n/a | yes |
| admin_username | Master DB username | `string` | `"dbadmin"` | no |
| allocated_storage | Initial storage in GB | `number` | `100` | no |
| db_name | Database instance identifier | `string` | `"fedramp-postgres-db"` | no |
| engine_version | PostgreSQL engine version. Give the major version only (for example "16") so that automatic minor version upgrades never show as drift; a full "major.minor" pins the starting minor version. The parameter group family is derived from the major version | `string` | `"16"` | no |
| instance_class | RDS DB instance compute class | `string` | `"db.r6g.large"` | no |
| log_retention_days | Retention period, in days, for the encrypted PostgreSQL and upgrade log groups | `number` | `365` | no |
| max_allocated_storage | Upper storage auto-scaling threshold in GB | `number` | `500` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| db_instance_arn | ARN of the RDS instance |
| db_instance_endpoint | Connection endpoint for the RDS instance |
| master_user_secret_arn | Secrets Manager secret ARN containing master database credentials |
<!-- END_TF_DOCS -->
