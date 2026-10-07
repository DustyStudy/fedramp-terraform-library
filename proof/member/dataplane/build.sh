#!/usr/bin/env bash
# Builds the db-client function package into ./build: the handler, the
# pure-Python PostgreSQL driver, the RDS certificate bundle and the role
# audit SQL from the rds-access-auditor module.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf build
mkdir build
python -m pip install --quiet --target build --no-compile "pg8000==1.31.2"
curl --fail --silent --show-error --output build/global-bundle.pem \
  https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
cp handler.py build/
cp ../../../modules/rds-access-auditor/sql/audit_postgres_roles.sql build/
