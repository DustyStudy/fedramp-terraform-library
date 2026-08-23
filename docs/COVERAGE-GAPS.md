# Coverage Gaps

Infrastructure-as-code can implement technical controls. It cannot write
your policies, train your staff, or run your incident response plan. This
document lists what a FedRAMP Moderate/High authorization requires that
**this repo does not and cannot provide** — so nobody mistakes "we deployed
this repo" for "we're FedRAMP ready."

## Entire control families this repo doesn't (and can't) address

| Family | Why it's out of scope |
|---|---|
| **PE** — Physical and Environmental Protection | Fully inherited from AWS's own FedRAMP authorization (data center access, fire suppression, power). Cite AWS's ATO package for this, not anything here. |
| **PS** — Personnel Security | Background checks, personnel screening, termination procedures — organizational HR process, not infrastructure. |
| **AT** — Awareness and Training | Security awareness training program and records — a training curriculum and LMS, not code. |
| **PM** — Program Management | Risk management strategy, security plan governance, insider threat program — organizational/policy documents. |
| **SA** — System and Services Acquisition | Vendor/supply-chain risk management for anything beyond AWS itself — a procurement process. |
| **PL** — Planning | The System Security Plan (SSP) itself. This repo can supply control-implementation *evidence* for your SSP (see `docs/control-mapping.md`), but the SSP is a document your organization writes, describing your specific system boundary — not something a template library produces. |
| **CA** — Assessment, Authorization, and Monitoring | The actual 3PAO assessment engagement, Security Assessment Plan (SAP), and Security Assessment Report (SAR) — see `CONTINUOUS-MONITORING.md` for what ongoing pieces of this you *can* automate evidence for. |

## Partial coverage — modules exist, but the control needs more than infra

- **IR-4/IR-6/IR-8 (Incident Response):** `modules/guardduty-org` and
  `moderate/incident-response` get findings into an SNS topic. That is
  detection and alerting, not an incident response *program*. FedRAMP
  expects a written IR plan, defined roles, an escalation path, and —
  critically — **tested** tabletop exercises. None of that exists in code.
- **CP-2/CP-4 (Contingency Planning):** `modules/org-governance` schedules
  backups; `modules/rds-postgres-hardened` is Multi-AZ. Neither of those is
  a Disaster Recovery *plan*, and FedRAMP's annual assessment specifically
  expects contingency plan testing — actually failing over and confirming
  recovery works, not just confirming backups exist.
- **CM-3/CM-4 (Change Control):** The GitHub Actions CI in this repo
  catches syntax and security-policy violations before merge. It is not a
  Change Advisory Board, a documented change-management process, or a
  Significant Change Request (SCR) process — FedRAMP requires CSPs to
  follow a formal SCR process with FedRAMP before making transformative
  changes to an authorized system.
- **RA-5 (Vulnerability Scanning):** GuardDuty and ECR scan-on-push give
  you continuous threat detection and container image scanning. FedRAMP's
  ConMon requirements go further — authenticated OS and application-level
  scans on a monthly cadence, uploaded as part of the monthly ConMon
  deliverable. See `CONTINUOUS-MONITORING.md`.
- **AC-2 (Account Management):** The password policy and MFA enforcement
  are automated. The actual account lifecycle — provisioning, periodic
  access review, timely offboarding — is a process your organization runs,
  not something Terraform/CloudFormation can enforce on its own.

## Technical gaps within what this repo does cover

- No explicit encryption-in-transit enforcement for anything outside the
  services this repo directly touches (RDS, S3 buckets it creates). If you
  add other data stores or internal services, you're responsible for their
  TLS configuration too.
- `fips-vpc-endpoints` only has genuine FIPS-suffixed endpoints for `kms`,
  `ec2`, and `sts` — see that module's `variables.tf` for why the rest
  aren't actually FIPS-specific endpoints.
- No web application firewall coverage beyond what `waf-hardened` attaches
  to — a WAF is only as good as what it's actually in front of.
- No explicit data classification or data loss prevention (DLP) tooling.

## The honest summary

This repo gets you a real head start on the *technical* control
implementation for FedRAMP Moderate/High — probably the single largest
chunk of implementation work by control count. It does not get you an
ATO. Budget separately, and early, for: your SSP, your IR and contingency
plans (written *and* tested), your personnel/training program, your 3PAO
engagement, and the ongoing ConMon operational load described in
`CONTINUOUS-MONITORING.md`.
