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

See `../docs/control-mapping.md` for detail on what's diverged and why.
