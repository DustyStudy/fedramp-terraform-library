# FedRAMP 20x & CR26 — The Plain-Language Cheat Sheet

If you've heard people worrying about "FedRAMP 20x" or "CR26" lately and
don't work in compliance for a living, this is for you. No acronyms left
unexplained, no assumption you already know what a 3PAO is.

**As of this writing (August 2026):** FedRAMP went through its biggest
overhaul since the program started in 2011. It's called the **Consolidated
Rules for 2026**, or **CR26**, and it finalized on June 24-25, 2026. This
doc explains what actually changed, why people are nervous about it, and
what's still true regardless.

⚠️ **This is a fast-moving program.** Treat every date and detail below as
"true as of when this was written," not gospel. The authoritative source
is always [fedramp.gov](https://www.fedramp.gov) and FedRAMP's own
[rules repository on GitHub](https://github.com/FedRAMP) — check there for
anything time-sensitive.

## The one thing to know first

**If a cloud service already had a "FedRAMP Authorization," it did not
lose it.** It just got renamed — the old authorization carries forward
under the new name, with the same controls and the same boundary. Nobody
has to redo work they already did just because of the terminology change.
That's the single most common misunderstanding driving unnecessary panic.

## Why people are actually anxious (the real reasons)

- **The vocabulary changed underneath everyone.** Terms companies have
  had baked into contracts, sales pages, and internal docs for years
  ("FedRAMP Authorized," "Moderate baseline") are being retired in favor
  of new terms. That's a real, if mostly cosmetic, scramble to update
  boilerplate.
- **Real deadlines, not just announcements.** FedRAMP Ready (a
  pre-authorization status many companies relied on as a sales credential)
  stopped accepting new submissions on July 28, 2026. Existing Rev5
  submissions have a cutoff in 2027. These aren't hypothetical — they're
  in motion now.
- **The "High" question isn't solved yet.** FedRAMP 20x was built with
  cloud-native SaaS in mind. The most demanding tier (formerly "High," now
  "Class D") still requires the older Rev5 process, and there's genuine
  open uncertainty — even among FedRAMP's own staff, publicly — about how
  the automation-first model extends to organizations running physical
  infrastructure.
- **The program itself has been through turnover and budget pressure**
  while rolling this out, which naturally slows guidance and creates
  understandable uncertainty about how smoothly the transition will go.
- **The whole philosophy is shifting**, not just the paperwork — from a
  once-a-year documentation review to continuous, machine-readable
  evidence about what's actually running in production, all the time.
  That's a real operational change for engineering teams, not just a
  compliance-team problem anymore.

## Old term → new term

| You used to hear | Now it's called | What actually changed |
|---|---|---|
| FedRAMP Authorized / Authorization | **FedRAMP Certified / Certification** | Just the label. Same underlying assessment concept. Agencies still separately issue their own "Authority to Operate" (ATO) — that word hasn't changed. |
| Low / Moderate / High (impact levels) | **Certification Class B / C / D** (with Class A as a new entry tier) | Important nuance: a Class is *not* a repackaged impact level. It describes how much evidence and reporting depth a cloud service commits to — not how sensitive the data it's allowed to hold is. Agencies still categorize their own systems as Low/Moderate/High separately; the two labels aren't meant to be read as equivalent. |
| 3PAO (Third Party Assessment Organization) | **FedRAMP Recognized Assessor** | Same idea — an independent assessor — new name, and a stricter rule that the assessor can't also be the same firm that advised you on getting ready. |
| Continuous Monitoring (ConMon) | **Collaborative Continuous Monitoring** | Same spirit (ongoing evidence, not just a point-in-time check), formalized with new specific deliverables (see below). |
| Significant Change Request (SCR) | **Significant Change Notification (SCN)** in some contexts | Philosophy shift from "ask permission" toward "notify," though exact terminology varies by which specific rule you're looking at — verify current usage for your situation. |

## The new Class system, in plain English

- **Class A** — a new, temporary entry tier. Lets a cloud service get a
  foot in the door using evidence it already has (like an existing SOC 2
  audit) instead of starting from zero. Time-limited — you're expected to
  move up to B, C, or D within a couple of years, not stay here forever.
- **Class B** — replaces what used to be called "Low."
- **Class C** — replaces what used to be called "Moderate."
- **Class D** — replaces what used to be called "High." This is the one
  still stuck on the older Rev5 process, still requires a federal agency
  to sponsor you, and is the most demanding tier by far.

## Two ways to get certified

- **Program Path** — new. FedRAMP itself reviews and certifies you
  directly, with no federal agency required to sponsor you first. This is
  the path essentially everyone pursuing 20x uses, and it removes what
  used to be one of the single biggest barriers to entry (finding an
  agency willing to sponsor a brand-new vendor).
- **Agency Path** — the traditional route. A federal agency reviews you
  first and sponsors your certification. Still the only path available
  for Class D ("High").

## FedRAMP 20x vs. FedRAMP Rev5 — the actual difference

- **Rev5** is the traditional approach: long written documents (a System
  Security Plan, assessment reports, a plan for fixing gaps), reviewed
  narratively by humans. It got modernized under CR26, but it's still
  fundamentally document-driven.
- **20x** replaces most of that narrative documentation with **Key
  Security Indicators (KSIs)** — specific, checkable facts about your
  system (e.g., "is MFA enforced," "are backups encrypted") that get
  verified in a machine-readable way, continuously, instead of written up
  once and read by a human. Reporting suggests dozens of these indicators
  grouped into several families — check FedRAMP's current published list
  directly, since the exact count and grouping has been refined more than
  once as the program matured.

If your service runs on standard cloud infrastructure you don't own
physically, 20x is very likely the path built for you. If you run your
own data centers, or need the "High" tier, you're still on Rev5 for now.

## Timeline (verify current dates before relying on these)

| Date | What happened / happens |
|---|---|
| June 24-25, 2026 | CR26 finalized and released |
| July 4, 2026 | CR26 takes effect for 20x cloud providers |
| July 28, 2026 | FedRAMP Ready stopped accepting new submissions |
| Aug 2026 | First 20x submission pipelines opened |
| Jan 1, 2027 | CR26 becomes mandatory for everyone, including existing Rev5 holders |
| ~Mid-2027 | New Rev5 applications close (Rev5 doesn't disappear immediately, but the door for *new* Rev5 submissions does) |
| FY2027 (targeted) | Class D ("High") pilot for the 20x model |
| Through ~2028 | Rev5 expected to fully sunset — exact date has shifted before and may again |

## What this actually means day-to-day for an engineering team

- Fewer giant Word documents, more continuous evidence pulled from actual
  running infrastructure — logs, config state, scan results.
- A push toward **OSCAL** (a machine-readable data format for compliance
  packages) — expect "does your tooling export OSCAL" to become an
  increasingly normal question from customers and auditors.
- Vulnerability management and configuration monitoring become an
  always-on discipline rather than a monthly report you assemble and
  forget about.

## Where this repo fits in

The NIST SP 800-53 controls underneath all of this — encryption, access
control, logging, incident response — **haven't changed**. What changed is
how you prove you've implemented them and what the paperwork is called.
That means:

- Everything in `docs/control-mapping.md` and
  `docs/NIST-800-53-REV5-MATRIX.md` stays relevant regardless of which
  Class or Type you're pursuing — those controls are the substance.
- The `fedramp-20x/` folder's KSI cross-reference was written against an
  earlier, six-category description of Key Security Indicators. Given
  CR26 has since formalized and likely expanded that structure, treat that
  folder's category list as directionally useful but due for a refresh
  against FedRAMP's current published KSI catalog — don't take the exact
  category names as current without checking.
- `docs/CONTINUOUS-MONITORING.md` describes the older monthly/annual
  ConMon deliverable model. CR26's "Collaborative Continuous Monitoring"
  formalizes new specific deliverables (Ongoing Certification Reports,
  Quarterly Reviews, Persistent Assessments) that aren't reflected there
  yet — same caveat, worth a dedicated update rather than assuming it's
  current.
- Nothing in `docs/COVERAGE-GAPS.md` changes either — the things this
  repo can't automate (personnel security, training, a tested incident
  response plan, the actual assessment engagement) are exactly as true
  under CR26 as they were before it.

## Where to actually check for current, authoritative information

- [fedramp.gov](https://www.fedramp.gov) — official site, changelog, and
  current rules
- [github.com/FedRAMP](https://github.com/FedRAMP) — the machine-readable
  rules themselves, which FedRAMP has said is the actual source of truth
  (ahead of any downloaded copy or third-party summary, including this one)
- FedRAMP's public roadmap and RFC (Request for Comment) postings for
  anything still being decided

This cheat sheet is a plain-language snapshot, not legal or compliance
guidance — for anything you're actually submitting to FedRAMP or an
agency, confirm against the current official rules directly.
