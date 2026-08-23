# Plan of Action & Milestones (POA&M) — Starter Template

Every real FedRAMP assessment finds gaps — that's expected, not a failure
state. A POA&M is how you track a finding from discovery through
remediation. **This is a lightweight starting point, not a substitute for
FedRAMP's official POA&M template**, which is an Excel workbook with a
specific required structure — get the current version from FedRAMP.gov
before submitting anything to an agency or the FedRAMP PMO. Use this file
to track findings informally (e.g., from your own Checkov/Trivy CI runs)
between formal submission cycles.

## Fields FedRAMP's official template expects

| Field | Description |
|---|---|
| POA&M ID | Unique identifier for this finding |
| Control ID | The NIST 800-53 control this finding relates to |
| Weakness Name / Description | What's wrong, in plain language |
| Source | Where this was found — vulnerability scan, Checkov/Trivy CI run, 3PAO assessment, penetration test, self-assessment |
| Asset(s) Affected | Which system/component |
| Risk Rating | Critical / High / Moderate / Low (per your scan tool's or 3PAO's rating) |
| Point of Contact | Who owns fixing this |
| Scheduled Completion Date | Per FedRAMP guidance: Critical findings ~30 days, High ~30 days, Moderate ~90 days, Low ~180 days from detection (confirm current timelines against your agency's ATO letter — these shift) |
| Milestones | Interim steps with their own target dates, not just a single end date |
| Status | Open / In Progress / Delayed / Completed / Risk Accepted (with agency AO sign-off) |
| Vendor Dependency | If remediation depends on AWS or a third party, note it — this affects your control over the completion date |

## Example row

| POA&M ID | Control ID | Weakness | Source | Risk | Scheduled Completion | Status |
|---|---|---|---|---|---|---|
| POAM-2026-001 | SC-28 | S3 bucket created outside this repo's modules found without default encryption | Checkov CI scan | Moderate | 90 days from detection | In Progress |

## Tying this repo's CI into your POA&M process

Every Checkov/Trivy finding that gets a `#checkov:skip` comment (or the
CFN `checkov: skip:` metadata block) in this repo is a *documented,
accepted* design decision — those are not POA&M candidates, they're
already-resolved risk acceptances with a stated reason.

Findings that block the CI (`soft_fail: false` on Checkov) and get fixed
before merge never reach a POA&M either — they're resolved before they
exist in a deployed environment.

Where a POA&M *does* apply: something the CI didn't catch, something
found in your actual deployed AWS account (drift from what's in this
repo), or something a 3PAO or agency scan surfaces that's outside this
repo's scope entirely (see `COVERAGE-GAPS.md`). Track those here or in
your official POA&M workbook — not as code comments.
