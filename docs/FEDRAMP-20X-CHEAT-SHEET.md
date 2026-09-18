# FedRAMP 20x / 2026 Consolidated Rules — Cheat Sheet

A plain-language rundown of what changed when FedRAMP launched the
"Consolidated Rules for 2026" (CR26) and moved 20x from pilot to a
generally available certification path. This is a summary for orienting
yourself quickly — always confirm against https://www.fedramp.gov/updates/changelog
before treating anything here as current.

## Terminology changes

| Old term | New term (2026) |
|---|---|
| FedRAMP Authorization | FedRAMP **Certification** |
| Low / Moderate / High baseline | Certification **Class B / C / D** |
| Rev5 control-by-control narrative | **Key Security Indicators (KSIs)** — outcome-based, machine-readable |
| FedRAMP Ready | Legacy pathway, closing — see timeline below |

## 2026 timeline

- **2026-06-24** — CR26 officially launches; 20x Class B ruleset and KSI
  cluster structure finalized (see `../fedramp-20x/README.md`)
- **2026-07-06** — Marketplace listings open under the new rules
- **2026-07-28** — Legacy "FedRAMP Ready" submission pathway closes
- **2026-08-03** — 20x Class A pipeline launches
- **2026-08-31** — 20x Class B/C pipelines launch
- **2026-09-09** — RFC-0033 (Class D development tracks) and RFC-0034
  (Technical Advisory Group changes) released
- **2027-01-01** — New rules become mandatory for all stakeholders
- **2027-06-11** — Last date a new Rev5 authorization can be granted;
  existing Rev5-authorized systems must transition to the new rules

## What this means for this repo

- **`moderate/` and `high/`** track Rev5 (soon-to-be-legacy) control
  baselines. They remain useful through the transition window, but any
  new engagement should default to the 20x/KSI path unless your agency
  sponsor specifically requires Rev5.
- **`fedramp-20x/`** tracks the finalized KSI cluster structure. See that
  folder's `README.md` for the current 10-cluster breakdown and which
  modules in this repo already contribute evidence toward each one.
- Machine-readable submission packages (OSCAL format — JSON/XML/YAML)
  are required for all providers as of September 2026 (RFC-0024). Nothing
  in this repo currently generates OSCAL output; that's a gap to be aware
  of if you're assembling an actual submission package.

## Where to verify this

- https://www.fedramp.gov/updates/changelog — day-to-day changes
- https://www.fedramp.gov/20x/ — 20x program landing page
- https://github.com/FedRAMP/rules — machine-readable consolidated rules
  dataset (successor to the now-archived `FedRAMP/docs`)
