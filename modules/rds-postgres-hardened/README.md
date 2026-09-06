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
| CP-9, CP-10, SC-8, SC-12, SC-28, IA-5 | KSI-SVC-02 |

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
- `engine_version` is pinned to `"16.3"` in `main.tf` (not exposed as a
  variable) — bump it there directly when you need a newer minor version,
  and confirm compatibility with `aws_db_parameter_group`'s
  `family = "postgres16"`.
