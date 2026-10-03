# rds-access-auditor

Audits how your RDS and Aurora databases can be reached and who can log
in to them, on a schedule: public exposure, master credentials, IAM
database authentication, TLS enforcement, and IAM policies that grant
`rds-db:connect` too broadly. **Detective only**. It never changes a
database, parameter group, security group or policy, because a surprise
reboot or a locked-out application is its own incident. A human reviews
and fixes.

[`rds-postgres-hardened`](../rds-postgres-hardened/) builds a database
that passes every check here. This module checks the databases that
weren't built that way: older ones, ones built by hand, and ones in
accounts you inherited.

## The risk this targets

Data-access paths are where an identity compromise turns into a breach.
The same patterns keep showing up:

- A database left publicly accessible "for a quick test", with a security
  group that admits `0.0.0.0/0`. Automated scanners find these within
  hours.
- Applications sharing the master user, which holds `rds_superuser` on
  PostgreSQL, through a static password nobody rotates.
- An IAM policy with `rds-db:connect` on `*`. With IAM database
  authentication that lets the caller log in as any database user,
  including the superuser.
- Clients allowed to connect without TLS.

## What it reports

| Check | Finding | Severity |
|---|---|---|
| Public access | Publicly accessible, and a security group admits `0.0.0.0/0` or `::/0` on the database port | CRITICAL |
| | Publicly accessible, security groups closed to the internet (one rule change away) | HIGH |
| `rds-db:connect` scope | IAM policy lets a principal connect as any database user (`*`, `dbuser:*`, `dbuser:<id>/*`) | HIGH |
| | IAM policy lets a principal connect as a database's master user | HIGH |
| | A partial wildcard in the user name (`dbuser:<id>/app_*`) | MEDIUM |
| Master credentials | Master password not managed by RDS in Secrets Manager | MEDIUM |
| Transport | `rds.force_ssl` (PostgreSQL, SQL Server) or `require_secure_transport` (MySQL, MariaDB) not on | MEDIUM |
| IAM authentication | IAM database authentication off (MySQL, MariaDB, PostgreSQL and their Aurora versions) | LOW |

Instances in an Aurora or Multi-AZ DB cluster take their credentials,
IAM authentication and TLS settings from the cluster, so those are
checked once on the cluster. Public access is checked per instance.
DocumentDB and Neptune, which the RDS API also returns, are skipped.

The `rds-db:connect` check reads inline policies on users, groups and
roles, and customer-managed policies that are attached to something. It
skips statements whose action is plain `"*"`: every administrator has
one, and flagging each would bury the grants that matter. Review
administrator access with
[`identity-center-access-auditor`](../identity-center-access-auditor/)
and IAM Access Analyzer instead.

Findings go to one SNS summary, grouped by severity. A clean run sends
nothing. An account the Lambda couldn't reach is listed under "Accounts
not scanned" rather than left out, so a failure never looks clean.

## What happens inside the database

The AWS API can't see database roles. Whether an application user holds
only `SELECT` on its schema, or quietly holds `rds_superuser`, needs a
database connection. The module leaves that out on purpose: an auditor
with network access and credentials to every database is a bigger risk
than the one it looks for.

[`sql/audit_postgres_roles.sql`](sql/audit_postgres_roles.sql) covers
that half for PostgreSQL 14 and later. It is read-only and lists:

1. Roles with superuser-like power: `rds_superuser` members, `CREATEROLE`
   or `BYPASSRLS`.
2. Login roles in `pg_read_all_data` or `pg_write_all_data`.
3. Login roles named like read-only users without
   `default_transaction_read_only = on`.
4. Schemas where `PUBLIC` can create objects.
5. Login roles with no password expiry that don't use IAM authentication
   (`rds_iam`).

```bash
psql "host=<endpoint> dbname=<db> user=<user> sslmode=verify-full" \
  -f modules/rds-access-auditor/sql/audit_postgres_roles.sql
```

CI runs it against PostgreSQL 16 with a fixture role for each finding
(`tests/sql/seed_rds_roles.sql`). The master user always shows up in
queries 1 and 5; that's expected. A least-privilege read-only role looks
like this:

```sql
CREATE ROLE app_readonly LOGIN;
GRANT rds_iam TO app_readonly;  -- IAM authentication, no static password
ALTER ROLE app_readonly SET default_transaction_read_only = on;
REVOKE ALL ON SCHEMA public FROM app_readonly;
GRANT USAGE ON SCHEMA app TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO app_readonly;
```

## Using Terraform

Single account:

```hcl
module "rds_access_auditor" {
  source = "../../modules/rds-access-auditor"

  notification_email = "you@example.com"
  regions            = ["us-east-1", "us-west-2"]
}
```

Whole organization: deploy in the management account or a delegated
administrator (the Lambda needs `organizations:ListAccounts`), and give
each member account a read-only role for it to assume.

```hcl
module "rds_access_auditor" {
  source = "../../modules/rds-access-auditor"

  notification_email = "you@example.com"
  regions            = ["us-east-1", "us-west-2"]
  member_role_name   = "rds-access-audit-read"
}

# In each member account (for example with a provider alias per account):
resource "aws_iam_role" "rds_access_audit_read" {
  name = "rds-access-audit-read"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = module.rds_access_auditor.lambda_role_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "rds_access_audit_read" {
  role   = aws_iam_role.rds_access_audit_read.id
  policy = module.rds_access_auditor.member_role_policy_json
}
```

An existing read-only audit role works too, if it allows
`rds:DescribeDBInstances`, `rds:DescribeDBClusters`,
`rds:DescribeDBParameters`, `rds:DescribeDBClusterParameters`,
`ec2:DescribeSecurityGroups` and `iam:GetAccountAuthorizationDetails` and
trusts the Lambda role.

Works the same in GovCloud. `use_fips_endpoint` defaults to `true`; every
API it calls resolves to a FIPS endpoint in us-east-1, us-east-2 and
us-west-2. Check the regions you list in `regions` if you add others.

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-3, AC-6, IA-2, IA-5, SC-7, SC-8 | KSI-IAM-ELP, KSI-IAM-SNU, KSI-CNA-RNT, KSI-SVC-ASM, KSI-SVC-SIN |

Supports the AC-6 review of who can reach data stores and as which
database user, and checks that authenticators (IA-5) and transport
encryption (SC-8) are managed rather than left at defaults. Detective
only: a human still decides what to change.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| code_signing_config_arn | Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip. | `string` | `null` | no |
| member_role_name | Name of a read-only role to assume in every other active account of the organization. Empty scans only the account the module is deployed in. The role must trust this module's Lambda role (output lambda_role_arn) and allow the actions in output member_role_policy_json. | `string` | `""` | no |
| name_prefix | Prefix used for naming all resources created by this module. | `string` | `"rds-access-auditor"` | no |
| notification_email | Optional email address to subscribe to the SNS topic. Leave empty to skip. | `string` | `""` | no |
| regions | Regions to audit RDS databases in. Empty means the region the module is deployed in. IAM roles are global and always audited. | `list(string)` | `[]` | no |
| schedule_expression | EventBridge schedule expression controlling how often the audit runs. | `string` | `"rate(1 day)"` | no |
| use_fips_endpoint | Make the Lambda's AWS SDK calls through FIPS 140 validated endpoints (sets AWS_USE_FIPS_ENDPOINT). Default true, matching the provider setting in this library's root configurations. | `bool` | `true` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| lambda_function_arn | ARN of the auditor Lambda function. |
| lambda_role_arn | ARN of the auditor's execution role. Member-account roles named by member_role_name must trust it. |
| member_role_policy_json | Read-only permissions the member-account role needs. Attach it to the role named by member_role_name in each account. |
| sns_topic_arn | ARN of the SNS topic used for audit notifications. |
<!-- END_TF_DOCS -->

## Notes

- A parameter that isn't set in the parameter group is reported as "not
  set (engine default)". PostgreSQL 15 and later default `rds.force_ssl`
  to `1` in the default parameter group, which does show a value; a custom
  group copied from an older version may not.
- Oracle and Db2 enforce TLS through option groups and listeners, not a
  parameter, so the transport check skips them.
- Public access is judged from security group rules only. Network ACLs,
  a missing internet gateway route, or a firewall can still block the
  traffic, so a CRITICAL here means "nothing in the security group stops
  it", not "confirmed reachable".
- This complements [`trust-policy-auditor`](../trust-policy-auditor/),
  which covers who outside the account can become a principal. This
  module covers what a principal can do with your databases once it is
  one.
