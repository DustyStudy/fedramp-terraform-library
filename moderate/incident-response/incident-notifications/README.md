# incident-notifications

Central incident-notification SNS topic that aggregates high-severity
findings from GuardDuty and Security Hub into a single feed.

## Usage

```hcl
module "incident_notifications" {
  source = "../../moderate/incident-response/incident-notifications"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| IR-4, IR-5, IR-6 | KSI-INR-01, KSI-INR-02 |

## Notes

This gets findings into one place. It is not an incident response plan —
see `docs/COVERAGE-GAPS.md` at the repo root for what FedRAMP expects
beyond alert routing (a written plan, defined roles, tested tabletop
exercises).
