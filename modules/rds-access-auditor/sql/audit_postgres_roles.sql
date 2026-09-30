-- Read-only review of database roles on an RDS or Aurora PostgreSQL
-- database: the in-engine half of the rds-access-auditor module, which
-- can only see the AWS control plane.
--
-- Run it as a user that can read pg_roles (any user can), for example:
--   psql "host=... dbname=... user=... sslmode=verify-full" -f audit_postgres_roles.sql
-- It changes nothing. Each query lists rows to review; an empty result is
-- clean.

\echo '1. Roles with superuser-like power (rds_superuser members, CREATEROLE, or BYPASSRLS)'
SELECT r.rolname,
       r.rolcanlogin AS can_login,
       pg_has_role(r.oid, 'rds_superuser', 'MEMBER') AS rds_superuser,
       r.rolcreaterole AS create_role,
       r.rolbypassrls AS bypass_rls
FROM pg_roles r
WHERE r.rolname NOT LIKE 'pg\_%'
  AND r.rolname NOT IN ('rds_superuser', 'rdsadmin', 'rds_replication', 'rds_password', 'rdsrepladmin')
  AND (pg_has_role(r.oid, 'rds_superuser', 'MEMBER') OR r.rolcreaterole OR r.rolbypassrls)
ORDER BY r.rolname;

\echo '2. Login roles that can read every table (pg_read_all_data) or write every table (pg_write_all_data)'
SELECT r.rolname,
       pg_has_role(r.oid, 'pg_read_all_data', 'MEMBER') AS read_all,
       pg_has_role(r.oid, 'pg_write_all_data', 'MEMBER') AS write_all
FROM pg_roles r
WHERE r.rolcanlogin
  AND r.rolname NOT IN ('rdsadmin')
  AND (pg_has_role(r.oid, 'pg_read_all_data', 'MEMBER') OR pg_has_role(r.oid, 'pg_write_all_data', 'MEMBER'))
ORDER BY r.rolname;

\echo '3. Login roles named like read-only users without default_transaction_read_only = on'
SELECT r.rolname, coalesce(array_to_string(s.setconfig, ', '), '(none)') AS role_settings
FROM pg_roles r
LEFT JOIN pg_db_role_setting s ON s.setrole = r.oid AND s.setdatabase = 0
WHERE r.rolcanlogin
  AND r.rolname ~* '(read|ro$|_ro_|report|analytics)'
  AND NOT coalesce('default_transaction_read_only=on' = ANY (s.setconfig), false)
ORDER BY r.rolname;

\echo '4. Schemas where PUBLIC (every role) can create objects'
SELECT n.nspname AS schema
FROM pg_namespace n
WHERE has_schema_privilege('public', n.oid, 'CREATE')
  AND n.nspname NOT LIKE 'pg\_%'
  AND n.nspname <> 'information_schema'
ORDER BY n.nspname;

\echo '5. Login roles with no password expiry that are not IAM-authenticated (rds_iam)'
SELECT r.rolname
FROM pg_roles r
WHERE r.rolcanlogin
  AND r.rolvaliduntil IS NULL
  AND NOT pg_has_role(r.oid, 'rds_iam', 'MEMBER')
  AND r.rolname NOT IN ('rdsadmin')
ORDER BY r.rolname;
