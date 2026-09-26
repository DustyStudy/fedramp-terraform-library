# Continuous Monitoring Mapping (CR26)

Certification isn't a one-time event — under FedRAMP's Consolidated Rules
for 2026 (CR26), providers keep reporting and detecting vulnerabilities for
as long as the service holds a FedRAMP Certification. This maps what CR26
actually requires against what this repo's modules generate evidence for,
and — just as importantly — what they don't.

Source: FedRAMP's machine-generated CR26 reference docs in
[github.com/FedRAMP/2026-markdown](https://github.com/FedRAMP/2026-markdown):
[`collaborative-continuous-monitoring.md`](https://github.com/FedRAMP/2026-markdown/blob/main/reference/collaborative-continuous-monitoring.md),
[`vulnerability-detection-and-response.md`](https://github.com/FedRAMP/2026-markdown/blob/main/reference/vulnerability-detection-and-response.md),
and [`significant-change-notification.md`](https://github.com/FedRAMP/2026-markdown/blob/main/reference/significant-change-notification.md)
(read September 2026). Rule wording and dates get revised — one CCM rule
carries a 2026-09-13 changelog entry — so verify against the live source
before relying on specifics here.

> **What replaced the old monthly ConMon model.** The pre-CR26 model
> (monthly POA&M, inventory, and vulnerability-scan deliverables, per the
> Nov 2025 Continuous Monitoring Playbook) is superseded by three CR26 rule
> sets: **Collaborative Continuous Monitoring** (quarterly reporting),
> **Vulnerability Detection and Response** (VDR — continuous, timeframe-driven
> detection and remediation instead of monthly scan packages), and
> **Significant Change Notification** (SCN — notify, don't ask permission).
> Rev5 holders keep their existing monthly obligations until they
> transition; the dates below say when each CR26 rule set binds.

## Applicability dates

| Rule set | 20x | Rev5 |
|---|---|---|
| Collaborative Continuous Monitoring (CCM) | Obtain 2026-07-04, Maintain 2027-01-01, grace ends at the first independent assessment started after 2027-01-01 | Obtain 2027-01-01, Maintain 2027-04-02, grace ends 2027-10-01 |
| Significant Change Notification (SCN) | Obtain 2026-07-04, Maintain 2027-01-01, grace ends at the first independent assessment started after 2027-01-01 | Obtain 2027-01-01, Maintain 2027-01-01, grace ends 2027-06-01 |
| Vulnerability Detection and Response (VDR) | Obtain and Maintain 2026-12-07, grace ends 2027-03-07 (both types; mandated by CISA BOD 26-04) | same |

Optional adoption opened 2026-07-04 for all three. "Maintain" means existing providers SHOULD adopt by that date (otherwise a corrective action plan is required); by the end of the grace period they MUST (otherwise certification is revoked).

## Quarterly reporting (CCM)

| CR26 requirement | What this repo helps with | What's still on you |
|---|---|---|
| **Ongoing Certification Report** every 3 months, human-readable, covering the whole period since the last one (`CCM-OCR-AVL`). Must summarize: changes to certification data, planned changes for the next 3+ months, accepted vulnerabilities, transformative changes, updated recommendations/best practices, agencies directly using the product, FedRAMP Reportable Incidents (or an attestation of none), and lessons learned from any incident | Evidence sources: `modules/config-conformance-pack` (configuration change history), `modules/guardduty-org` and `modules/security-hub-org` (findings history), `modules/org-cloudtrail` (change audit trail), `CHANGELOG.md` (change record) | Writing the report, the agency list, the accepted-vulnerability list, and the incident attestation — none of that is infrastructure |
| Publish the next report's target date (`CCM-OCR-NRD`); provide an async feedback channel (`CCM-OCR-FBM`); publish an anonymized feedback summary (`CCM-OCR-AFS`) | Nothing | All operational |
| **Quarterly Review** meeting every 3 months — MUST for Class C/D, SHOULD for Class B, MAY for Class A (`CCM-QTR-MTG`); registration link or calendar file (`CCM-QTR-REG`); publish next review date (`CCM-QTR-NRD`); SHOULD be scheduled 3–10 business days after each report (`CCM-QTR-SAR`) | Nothing | All operational |
| Don't irresponsibly disclose sensitive information in reports or reviews (`CCM-OCR-LSI`, `CCM-QTR-NID`) | Nothing | Editorial judgment about what a report can safely say |

## Vulnerability detection and response (VDR)

VDR replaces the monthly "scan results" deliverable with continuous,
automation-first detection and remediation on fixed timeframes.

| CR26 requirement | What this repo helps with | What's still on you |
|---|---|---|
| Persistently detect vulnerabilities (`VDR-CSO-DET`), track and remediate them (`VDR-CSO-RES`), treat failures of the detection process itself as vulnerabilities (`VDR-CSO-FAV`) | `modules/guardduty-org` (threat detection), `modules/security-hub-org` (findings aggregation), `modules/ecr-hardened` (scan-on-push), `modules/ssm-patching-hardened` (automated patching) | An OS/application-level vulnerability scanner with credentialed coverage — GuardDuty and ECR scanning are not a substitute — plus the triage and remediation workflow |
| Machine-based resource verification and validation on a fixed cadence — for 20x, every 7 days (Class B) or every 3 days (Class C) (`VDR-TFR-MVX`); for Rev5, monthly (`VDR-TFR-MVF`) | `modules/config-conformance-pack` evaluates configuration continuously, which satisfies the cadence in substance for configuration state | Confirming your rule/benchmark selection matches what your assessor expects; vulnerability detection is a separate activity |
| Vulnerability detection on resources likely to drift at least every 3 months (Class A) / monthly (B) / 14 days (C) / 7 days (D) (`VDR-TFR-PDD`, SHOULD); on resources not likely to drift every 6 months (A, B) / monthly (C, D) (`VDR-TFR-PCD`, SHOULD) | `modules/config-conformance-pack` flags configuration drift on managed resources | Deciding which resources are "likely to drift" and running detection at the required interval |
| Non-machine resources (people, process, documents) verified every 3 months (`VDR-TFR-NMV`) | Nothing | All operational |
| Mitigate/remediate within timeframes set by Potential Agency Impact rating, internet reachability and exploitability (`VDR-TFR-PVR`); remediate Known Exploited Vulnerabilities per the CISA KEV catalog dates (`VDR-TFR-KEV`, CISA BOD 26-04); avoid deploying new resources with KEVs (`VDR-CSO-AKE`) | `modules/ssm-patching-hardened` sets a 7-day critical-patch approval delay for instances it manages | Everything above that — triage, exception tracking, container/image rebuilds. Report open and accepted vulnerabilities under the VER rules (`VER-TFR-MHR` monthly report with `VER-RPT-VDT` / `VER-RPT-AVI` fields); under CR26 this replaces the provider POA&M (`POAM-TEMPLATE.md` is kept for legacy Rev5 packages only) |
| Detect after changes (`VDR-CSO-DAC`) and design for resilience (`VDR-CSO-DFR`) | CI (Checkov, Trivy, TFLint) checks modules before deploy — useful, but not runtime detection | Automated detection on representative samples of new or significantly changed running resources |

## Significant Change Notification (SCN)

SCN replaces the Significant Change Request approval process. Providers
evaluate each potential change (`SCN-CSO-EVA`) and sort it:

| Category | Requirement |
|---|---|
| Routine recurring — regularly recurs as part of ongoing operations, vulnerability mitigation, or remediation | No formal notification (`SCN-RTR-NNR`) |
| Adaptive — doesn't routinely recur and doesn't introduce substantive risks needing in-depth assessment | Notify necessary parties within 10 business days after finishing (`SCN-ADP-NTF`), including any new risks or vulnerabilities |
| Transformative — introduces substantive risks likely to affect existing risk determinations; typically major new features or capabilities | Notify initial plans at least 30 business days before starting (`SCN-TRF-NIP`) and final plans at least 10 business days before (`SCN-TRF-NFP`), plus notification after finishing and after verification |
| Change of Certification Class | Not an SCN — requires a new assessment |

Nothing in this repo's CI classifies changes or sends notifications. The
change record it does produce (git history, PRs, `CHANGELOG.md`, CloudTrail)
supports the audit records SCN expects providers to maintain
(the "Maintain Audit Records" rule). Classification is a judgment call
your compliance team makes per change.

## Continuous evidence this repo generates

| Expectation | What this repo provides |
|---|---|
| Continuous audit logging (KSI-MLA-LET, KSI-MLA-OSM) | `modules/org-cloudtrail` + `moderate/logging-monitoring`'s 14 CIS alarms |
| Continuous configuration monitoring (KSI-SVC-ACM, KSI-MLA-EVC) | `modules/config-conformance-pack` |
| Continuous threat detection and posture monitoring | `modules/guardduty-org`, `modules/security-hub-org` |
| Incident alerting | `moderate/incident-response`'s aggregated SNS topic |

## Annual and assessment-related work

| Requirement | This repo's relevance |
|---|---|
| Independent assessment (FedRAMP Recognized Assessor, formerly 3PAO) | The evidence this repo's modules generate (Config history, CloudTrail logs, GuardDuty finding history) supports an assessment, but the assessment itself is an external engagement |
| Incident response and recovery testing (KSI-INR-*, KSI-RPL-TRC) | Not addressed by this repo — see `COVERAGE-GAPS.md`. Detection tooling is not the same as a tested IR plan |
| Deviation / risk-acceptance decisions | A risk decision by your organization and, where applicable, your agency customers — not something infrastructure generates |

## The gap this doc doesn't paper over

Everything in the tables above that says "what's still on you" is real,
ongoing operational work — quarterly reports and meetings, remediation on
fixed clocks, change classification — for as long as the service holds a
certification. Deploying this repo gives you strong technical evidence
generation. It doesn't reduce that operational burden to zero, and nobody
should represent it that way in an assessment or to an agency.
