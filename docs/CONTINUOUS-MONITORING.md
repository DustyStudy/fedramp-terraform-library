# Continuous Monitoring (ConMon) Mapping

An ATO isn't a one-time event — FedRAMP's Continuous Monitoring (ConMon)
program requires ongoing deliverables for as long as the system stays
authorized. This maps what FedRAMP actually requires against what this
repo's modules generate evidence for, and — just as importantly — what
they don't.

Source: FedRAMP's Continuous Monitoring Playbook (v1.0, Nov 2025) and
related FedRAMP.gov guidance. Verify current requirements at
https://www.fedramp.gov before relying on specifics here — ConMon
requirements have been updated multiple times and will be again.

## Monthly deliverables

| FedRAMP Requirement | What this repo helps with | What's still on you |
|---|---|---|
| Updated POA&M | See `POAM-TEMPLATE.md` | Actually tracking and closing findings — the template doesn't do this for you |
| Updated system inventory | `modules/config-conformance-pack` gives you a continuously current resource inventory via AWS Config | Formatting it into FedRAMP's required inventory template and uploading it |
| Vulnerability scan results | `modules/guardduty-org` (threat detection), `modules/ecr-hardened` (image scan-on-push) | Authenticated OS/application-level vulnerability scans — GuardDuty and ECR scanning are not a substitute for a proper credentialed scanner (e.g., Tenable, Qualys) run monthly against your instances/containers |
| Monthly Service Configuration Scans (CA-7 additional requirement) | `modules/config-conformance-pack`'s conformance pack runs continuously, which covers this in substance | Confirming your specific conformance pack/benchmark selection matches what your 3PAO expects, and exporting/uploading results in the required format |
| Deviation requests (for anything missing an SLA) | N/A | This is a formal risk-acceptance process with your Agency AO — not something infrastructure generates |

## Continuous/real-time evidence

| FedRAMP Expectation | What this repo provides |
|---|---|
| Continuous audit logging (AU-2, AU-6) | `modules/org-cloudtrail` + `moderate/logging-monitoring`'s 14 CIS alarms |
| Continuous configuration monitoring (CM-6) | `modules/config-conformance-pack` |
| Continuous threat detection (SI-4) | `modules/guardduty-org`, `modules/security-hub-org` |
| Incident detection/alerting (IR-4) | `moderate/incident-response`'s aggregated SNS topic |

## Annual deliverables

| FedRAMP Requirement | This repo's relevance |
|---|---|
| Annual control reassessment | The evidence this repo's modules generate (Config history, CloudTrail logs, GuardDuty finding history) supports a 3PAO's annual assessment, but the assessment itself is an external engagement, not something automated |
| Security Assessment Plan (SAP) / Security Assessment Report (SAR) | Written by your 3PAO — outside this repo's scope entirely |
| Incident response and contingency plan testing | Not addressed by this repo at all — see `COVERAGE-GAPS.md`. Detection tooling (GuardDuty) is not the same as a tested IR plan |

## Significant Change Requests (SCRs)

FedRAMP distinguishes routine recurring changes (patch a Lambda, rotate a
password policy value) from transformative changes (new service category,
major architecture shift) that require a formal SCR process with FedRAMP
before deployment to a production authorized boundary. Nothing in this
repo's CI enforces or tracks that distinction — that's a judgment call
your compliance team makes per change, informed by FedRAMP's Continuous
Monitoring Playbook (see "Significant Changes" section).

## The gap this doc doesn't paper over

Everything in the tables above that says "what's still on you" is real,
ongoing operational work — most of it recurring monthly or annually,
indefinitely, for as long as the system holds an ATO. Deploying this repo
gives you strong technical evidence generation. It doesn't reduce that
ongoing operational burden to zero, and nobody should represent it that
way in an SSP or to a 3PAO.
