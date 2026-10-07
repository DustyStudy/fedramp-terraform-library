"""Connects to the hardened database from inside the VPC and reports what it allowed.

Runs as the proof stack's db-client function. It never returns a password
or a token: each step reports only whether the connection was accepted and
what the server said.
"""

import json
import os
import re
import ssl
from pathlib import Path

import boto3
import pg8000.native

HOST = os.environ["DB_HOST"]
IAM_USER = os.environ["DB_IAM_USER"]
HERE = Path(__file__).parent


def connect(user, password, tls=True):
    # The RDS certificate bundle is the only trust anchor, and the hostname
    # is checked, so a TLS connection here is a verified one.
    # False, not None: pg8000 treats None as "use TLS if the server offers it".
    context = ssl.create_default_context(cafile=str(HERE / "global-bundle.pem")) if tls else False
    return pg8000.native.Connection(user, host=HOST, database="postgres", password=password, ssl_context=context, timeout=15)


def attempt(fn):
    try:
        return {"accepted": True, "observed": fn()}
    except Exception as exc:  # noqa: BLE001 - the server's refusal is the evidence
        return {"accepted": False, "observed": f"{type(exc).__name__}: {str(exc)[:300]}"}


def query(user, password, sql, tls=True):
    connection = connect(user, password, tls)
    try:
        return connection.run(sql)
    finally:
        connection.close()


def audit_statements():
    # The file is written for psql. Drop its \echo lines and comments, and
    # run each query on its own.
    text = (HERE / "audit_postgres_roles.sql").read_text(encoding="utf-8")
    text = "\n".join(line for line in text.splitlines() if not line.startswith(("\\", "--")))
    return [statement.strip() for statement in text.split(";") if statement.strip()]


def handler(_event, _context):
    secret = json.loads(boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["SECRET_ARN"])["SecretString"])
    master, password = secret["username"], secret["password"]
    report = {}

    report["master_without_tls"] = attempt(lambda: query(master, password, "select 1", tls=False))
    report["master_with_verified_tls"] = attempt(
        lambda: query(master, password, "select version, cipher from pg_stat_ssl where pid = pg_backend_pid()")
    )

    query(master, password, f"drop role if exists {IAM_USER}")
    query(master, password, f"create role {IAM_USER} login")
    query(master, password, f"grant rds_iam to {IAM_USER}")
    try:
        token = boto3.client("rds").generate_db_auth_token(DBHostname=HOST, Port=5432, DBUsername=IAM_USER)
        report["iam_token_with_tls"] = attempt(lambda: query(IAM_USER, token, "select current_user"))
        report["iam_user_with_a_password"] = attempt(lambda: query(IAM_USER, "not-a-token", "select 1"))
        report["iam_token_without_tls"] = attempt(lambda: query(IAM_USER, token, "select 1", tls=False))

        audit = []
        for statement in audit_statements():
            rows = attempt(lambda statement=statement: query(master, password, statement))
            first_line = re.sub(r"\s+", " ", statement)[:80]
            audit.append({"query": first_line, **rows})
        report["role_audit_sql"] = audit
    finally:
        query(master, password, f"drop role if exists {IAM_USER}")
    return report
