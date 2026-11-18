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
| IR-4, IR-5, IR-6 | KSI-INR-RIR, KSI-INR-AAR |

## Notes

This gets findings into one place. It is not an incident response plan —
see `docs/COVERAGE-GAPS.md` at the repo root for what FedRAMP expects
beyond alert routing (a written plan, defined roles, tested tabletop
exercises).

The Security Hub rule routes only active (not archived) findings and, by
default, leaves GuardDuty findings to the GuardDuty rule so each one is
delivered once. That assumes GuardDuty events reach the same event bus:
if Security Hub here aggregates other regions or accounts and GuardDuty
does not, set `exclude_guardduty_from_securityhub = false`.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| exclude_guardduty_from_securityhub | Leave GuardDuty findings out of the Security Hub rule, so a finding the GuardDuty rule already routed is not delivered a second time. Set false if Security Hub in this account and region aggregates findings from regions or accounts whose GuardDuty events do not reach this event bus; those would otherwise not be routed at all. | `bool` | `true` | no |
| guardduty_severity_threshold | Minimum GuardDuty finding severity to route here (7.0+ is High per GuardDuty's severity scale; 4.0-6.9 is Medium, 0.1-3.9 is Low). | `number` | `7` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| incident_notification_topic_arn | Central SNS topic for high-severity security findings — subscribe your ticketing system, SOAR pipeline, or on-call paging integration. |
<!-- END_TF_DOCS -->
