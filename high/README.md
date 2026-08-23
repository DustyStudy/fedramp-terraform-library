# FedRAMP High

Reuses the `moderate/` modules with tighter variable values via `.tfvars`
overrides rather than duplicating module code. Only add a module here if
it diverges *structurally* from its Moderate counterpart — for example:

- FIPS 140-3 validated cryptographic endpoint enforcement
- Extended audit log retention (High commonly expects longer retention
  windows than Moderate — confirm current figures against your SSP)
- Additional audit event types or more restrictive network segmentation

Where a Moderate module only needs different **variable values** (e.g.
`log_retention_days`), apply the same Moderate module with a High
`.tfvars` file instead of duplicating the module here. See
`example-tfvars/` for illustrative examples of this pattern — the exact
figures in those files are starting points, not universal FedRAMP High
requirements; retention windows and other numeric thresholds vary by
agency SSP, so confirm them against yours before using them as-is.

## What's here

| Folder | Status |
|---|---|
| `account-baseline/` | Calls `modules/account-baseline` with a dedicated High-tier KMS key and a 16-character minimum password length |
| `org-governance/` | Calls `modules/org-governance` with a 1095-day (3-year) backup retention |
| `org-scp-boundary/` | Calls `modules/org-scp-boundary` with the High policy name |
| `example-tfvars/` | Illustrative variable overrides — see the caveat above |

See `../docs/control-mapping.md` for detail on what's diverged and why.
