# stale-account-detector

Scans every **ACTIVE** account in the AWS Organization for CloudTrail
activity in the last N days, using an organization-wide **CloudTrail
Lake** event data store queried with plain SQL — no Athena/Glue setup,
no per-account role assumption. Emails a report via SNS **only when it
actually finds stale accounts** — a scan that finds nothing sends no
email at all.

> **CloudTrail Lake availability.** AWS no longer accepts new CloudTrail
> Lake customers: in an organization that has never used it,
> `CreateEventDataStore` fails with "CloudTrail Lake is no longer accepting
> new customers" (seen in the [live run](../../docs/LIVE-PROOF.md) on
> 2026-10-04). This module works where CloudTrail Lake is already in use.
> Pass an existing store with `create_event_data_store = false` and
> `existing_event_data_store_arn`.

## Why CloudTrail Lake instead of parsing raw CloudTrail logs

CloudTrail Lake is purpose-built for exactly this kind of ad-hoc,
cross-account SQL query. The alternative — Athena over the raw S3
CloudTrail logs from an [`org-cloudtrail`](../org-cloudtrail/)
trail — works too, but means you maintain Glue table partitioning
yourself. This module creates and queries its own event data store
instead (or reuses an existing one, see below).

## How "stale" is determined

1. List every `ACTIVE` account in the Organization.
2. Run one CloudTrail Lake query covering the last
   `activity_lookback_days` days, grouped by `recipientAccountId`,
   returning each account's most recent event of any kind and its most
   recent `ConsoleLogin` event specifically.
3. Any `ACTIVE` account with **no row** in those results had zero
   recorded CloudTrail activity (management events) in the lookback
   window — that's what gets reported as stale.
4. Accounts that show up with only non-interactive API activity (no
   `ConsoleLogin`) are **not** treated as stale, but are called out
   separately in the report for context.

This only sees what's actually in the event data store: if the store is
newer than the lookback period, "no activity in N days" means "no
activity since the store started ingesting," not "no activity ever."

## Usage

Apply from the Organizations **management account**, or a registered
delegated administrator for CloudTrail.

```hcl
module "stale_account_detector" {
  source = "../../modules/stale-account-detector"

  notification_email     = "you@example.com"
  activity_lookback_days = 90
  schedule_expression    = "rate(7 days)"
}
```

To reuse an existing organization-wide event data store instead of
creating a new one (recommended if you already have one — CloudTrail
Lake bills by ingestion volume):

```hcl
  create_event_data_store        = false
  existing_event_data_store_arn  = "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Requires the `hashicorp/archive` provider in addition to `hashicorp/aws`.
Works the same in GovCloud.

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-2, AC-2(3), CM-8 | KSI-IAM-AAM |

Flags accounts to disable or close; it doesn't disable anything itself.
The account-level counterpart to AC-2(3)'s "disable inactive accounts".

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| activity_lookback_days | Accounts with no CloudTrail activity in this many days are reported as stale. Also bounds the CloudTrail Lake query window - keep this at or below the event data store's actual retention period. | `number` | `90` | no |
| code_signing_config_arn | Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip. | `string` | `null` | no |
| create_event_data_store | Create a new organization-wide CloudTrail Lake event data store (management events only, scoped to keep ingestion cost down). Set to false if you already have a suitable one and supply its ARN via existing_event_data_store_arn instead - CloudTrail Lake bills by ingestion volume, so avoid standing up a duplicate store just for this tool if one already exists. | `bool` | `true` | no |
| event_data_store_retention_days | Retention period (days) for the event data store this module creates. Ignored if create_event_data_store is false. Minimum supported by CloudTrail Lake is 7 days; keep this comfortably above activity_lookback_days. | `number` | `92` | no |
| excluded_account_ids | Account IDs to always skip (break-glass accounts, intentionally idle sandboxes, log-archive accounts, etc.). | `list(string)` | `[]` | no |
| exempt_tag_key | Optional AWS Organizations account tag key. Accounts carrying this tag are skipped entirely. Leave empty to check every account. | `string` | `""` | no |
| exempt_tag_value | Optional value exempt_tag_key must match. Leave empty to exempt on the tag key's presence alone (any value). | `string` | `""` | no |
| existing_event_data_store_arn | ARN of an existing organization-wide CloudTrail Lake event data store to query instead of creating a new one. Required if create_event_data_store is false. It must be organization-enabled and include management events, or this tool won't see activity from member accounts. | `string` | `""` | no |
| name_prefix | Prefix used for naming all resources created by this module. | `string` | `"stale-account-detector"` | no |
| notification_email | Optional email address to subscribe to the SNS topic for the stale-account report. Leave empty to skip. | `string` | `""` | no |
| schedule_expression | EventBridge schedule expression controlling how often the scan runs. | `string` | `"rate(7 days)"` | no |
| reserved_concurrent_executions | Concurrency reserved for the Lambda. Set -1 to reserve none: accounts at the 10-execution quota floor (new and sandbox accounts) reject any reservation. | `number` | `1` | no |
| use_fips_endpoint | Make the Lambda's AWS SDK calls through FIPS 140 validated endpoints (sets AWS_USE_FIPS_ENDPOINT). Default true, matching the provider setting in this library's root configurations. | `bool` | `true` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| event_data_store_arn | ARN of the CloudTrail Lake event data store being queried (created by this module, or the existing one you supplied). |
| lambda_function_arn | ARN of the stale-account detector Lambda function. |
| sns_topic_arn | ARN of the SNS topic used for the stale-account report. |
<!-- END_TF_DOCS -->

## Notes

- The Lambda honors `EXEMPT_TAG_VALUE` only when it's non-empty, so
  leaving `exempt_tag_value` unset exempts on the tag key alone.
- The event data store this module creates is scoped to **management
  events only** — data events are high-volume and costlier to ingest,
  and account staleness only needs to know whether *anyone did anything*
  in an account, which management events already capture, including
  `ConsoleLogin`.
- `termination_protection_enabled = true` on the created event data
  store — deleting it also deletes its ingested history, so `terraform
  destroy` won't remove it until you explicitly disable termination
  protection first.
- The event data store is encrypted with the same customer-managed KMS
  key used for the Lambda's log group — **once associated, that key
  can't later be removed or changed** on the event data store (an AWS
  CloudTrail Lake constraint, not something this module can work
  around). Plan your key accordingly before the first apply.
- If your organization already has [`org-cloudtrail`](../org-cloudtrail/)
  deployed, that's a **separate** resource from a CloudTrail Lake event
  data store (different pricing model, different query mechanism) — this
  module doesn't read from that trail's S3 bucket directly.
- Consider starting with a longer `activity_lookback_days` (e.g. 180)
  for the first run or two, since a newly-created event data store has
  no history yet and every account will look "stale" until it's
  ingested enough real activity to tell the difference.
