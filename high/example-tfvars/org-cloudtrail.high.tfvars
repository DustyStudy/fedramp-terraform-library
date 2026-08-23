# Illustrative example of the "reuse the Moderate module, override the
# variables" pattern described in ../README.md — not asserted FedRAMP High
# requirements. Retention windows are set by your agency's SSP, not a
# single universal FedRAMP figure; adapt these, don't copy them verbatim.
#
# Usage:
#   terraform apply -var-file=example-tfvars/org-cloudtrail.high.tfvars

log_retention_days    = 1096 # ~3 years, up from Moderate's 365-day default
s3_log_retention_days = 2555 # ~7 years — same as Moderate's default
