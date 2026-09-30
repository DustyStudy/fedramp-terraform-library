-- Fixture for modules/rds-access-auditor/sql/audit_postgres_roles.sql:
-- stand-ins for the roles RDS creates, plus one role per finding the
-- audit should report and one it shouldn't.
CREATE ROLE rds_superuser;
CREATE ROLE rds_iam;
CREATE ROLE rdsadmin LOGIN;

CREATE ROLE fixture_master LOGIN IN ROLE rds_superuser;
CREATE ROLE fixture_role_admin LOGIN CREATEROLE;
CREATE ROLE fixture_writer LOGIN IN ROLE rds_iam, pg_write_all_data;
CREATE ROLE fixture_readonly LOGIN;
CREATE ROLE fixture_report_ro LOGIN IN ROLE rds_iam;
ALTER ROLE fixture_report_ro SET default_transaction_read_only = on;

CREATE SCHEMA fixture_open;
GRANT CREATE ON SCHEMA fixture_open TO PUBLIC;
