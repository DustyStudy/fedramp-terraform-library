# secret-access-burst-detector

Reports any principal that is denied many API calls and also reads a
secret or parameter within the same short window. A scheduled Lambda runs
CloudWatch Logs Insights queries over the CloudTrail log group and joins
the two results per principal. **Detective only**: it never disables a
credential or changes a policy. **Off by default**: see
[Turning it on](#turning-it-on).

## The risk this targets

A stolen credential gets tried against everything it might reach. In the
AntiFox-linked intrusions Arctic Wolf Labs described on 2026-11-10
([summary](https://www.esecurityplanet.com/news/news-antifox-aws-credential-theft-cloudtrail/)),
an attacker made hundreds of AWS API calls across several identities in
about 30 minutes. Most were denied. One
[`GetSecretValue`](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
succeeded and returned a production secret. Wiz documented the same kind
of secret harvesting through
[Qubole's cross-account access](https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild).

[`logging-monitoring`](../logging-monitoring/) already watches both
halves, but separately:

- `cis-unauthorized-api-calls` alarms on any single denied call. In a
  busy account it is in alarm most of the day, so a burst from one
  principal does not stand out.
- `cis-unexpected-secret-reads` (opt-in) alarms on secret and parameter
  reads by principals not listed in `expected_secret_readers`. A stolen
  credential that *is* an expected reader passes it.

Neither correlates per identity. This module does: the same principal,
many denials, and a successful secret read, all inside one window. Keep
both `logging-monitoring` alarms; this adds to them and replaces neither.

## How it works

An EventBridge rule (default: every 15 minutes) invokes the Lambda, which
looks back `query_window_minutes` (default 60):

1. **Denied calls per principal.** A Logs Insights query counts records
   whose `errorCode` matches `AccessDenied*` or `*UnauthorizedOperation`
   (the same codes as `logging-monitoring`'s `UnauthorizedApiCalls`
   filter), grouped by `userIdentity.arn`.
2. **Successful secret reads**, only if some principal reached
   `denied_call_threshold` (default 20): records with no `errorCode` for
   `secretsmanager` `GetSecretValue` and `ssm` `GetParameter`,
   `GetParameters`, `GetParametersByPath` and `GetParameterHistory` (the
   same events as `logging-monitoring`'s `UnexpectedSecretReads` filter).

A principal in both results is a finding. Each run publishes at most one
SNS message, listing for every finding the principal, its denied-call
count with first and last time, and each secret or parameter it read with
first and last time. No findings, no message.

Things to know:

- The order inside the window is not checked. Denials after the read
  count the same as denials before it.
- Windows overlap (60 minutes of data every 15), so a burst that spans a
  run boundary is still caught, and the same finding is reported by
  every run whose window holds it: up to four times with the defaults.
- A burst and a read are reliably correlated only when they are no
  further apart than `query_window_minutes` minus the schedule interval
  minus the CloudTrail delivery delay (about 5 minutes): 40 minutes with
  the defaults. Further apart, it depends on when a run happens to fire.
- An assumed-role session is its own principal
  (`arn:<partition>:sts::<account>:assumed-role/<role>/<session>`), so
  denials spread over many sessions of one role are counted per session.
  Records without `userIdentity.arn` are not correlated.
- A failed query, a failed publish, or a denied-call or secret-read
  result at the Logs Insights row limit (10,000, so possibly incomplete)
  fails the invocation instead of counting as clean. Failed runs are not retried;
  they go to the dead-letter queue, and two CloudWatch alarms (Lambda
  `Errors`, queue depth) notify the same SNS topic. The module sets the
  topic's policy so those alarms can publish; attaching your own
  `aws_sns_topic_policy` would replace it.

## Using Terraform

```hcl
module "secret_access_burst_detector" {
  source = "../../modules/secret-access-burst-detector"

  cloudtrail_log_group_name = module.org_cloudtrail.log_group_name
  notification_email        = "you@example.com"

  enabled = false # the default; see "Turning it on"
}
```

Deploy it in the account and region that hold the CloudTrail log group.
Works the same in GovCloud: every ARN is built from the current
partition, and `use_fips_endpoint` defaults to `true`.

## Turning it on

With `enabled = false` everything is created but the EventBridge rule is
`DISABLED`: no queries run, nothing is charged for queries, and nothing
alerts. Enable it per account, after a tuning period:

1. **Confirm the events are there.** Check that `GetSecretValue` events
   appear in the CloudTrail log group before relying on this (run a
   Logs Insights query for `eventName = "GetSecretValue"` over a day).
   `logging-monitoring`'s secret-read filter has the same dependency. If
   the trail does not deliver them to this log group, the module finds
   nothing and says nothing.
2. **Tune while it is off.** Invoke the function by hand a few times
   across a normal working day and read the result and the SNS messages.
   The main risk is alert noise: legitimate automation that probes and
   gets denied (inventory and compliance scanners, deployment tools that
   try a call and fall back) and also reads a secret looks exactly like
   the attack. Raise `denied_call_threshold`, or list that automation in
   `ignored_principal_arns`. Keep that list short: an ignored principal
   whose credential is stolen is not detected.
3. **Check the cost.** Logs Insights charges for the log data each query
   scans, so cost grows with the CloudTrail log group's volume, the
   window, and the schedule: by default 96 runs a day, each scanning 60
   minutes of logs once, or twice when a principal crosses the threshold.
   An organization trail's log group can be large.
4. Set `enabled = true` and apply.

## Deployment and rollback

- **Breaking-change risk: none for existing workloads.** The module only
  reads CloudTrail logs and publishes to its own SNS topic. It changes no
  existing resource and blocks nothing.
- **What it costs while off:** one KMS key and a few idle resources.
- **Rollback:** set `enabled = false` to stop the runs and keep
  everything else, or remove the module block and apply. The KMS key is
  then scheduled for deletion after 30 days; the Lambda's log group is
  deleted with the module, so export it first if you need the history.

## Lambda permissions

| Action | Resource | Why |
|---|---|---|
| `logs:StartQuery`, `logs:GetQueryResults` | The CloudTrail log group only | Both ARN forms (with and without the trailing `:*`) so the grant matches however IAM presents the log group |
| `logs:CreateLogStream`, `logs:PutLogEvents` | Its own log group | Terraform creates the group, so the role cannot create log groups |
| `sns:Publish` | The module's topic | Findings |
| `sqs:SendMessage` | The module's dead-letter queue | Failed runs |
| `kms:Decrypt`, `kms:GenerateDataKey*` | The module's CMK | Encrypted topic, queue and environment variables |
| `xray:PutTraceSegments`, `xray:PutTelemetryRecords` | `*` | Active tracing; X-Ray has no resource to scope to |

The topic, the dead-letter queue, the Lambda's log group and its
environment variables are encrypted with the module's own
customer-managed key (rotation on, 30-day deletion window).

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| SI-4, AU-6, AU-2, AU-12 | KSI-MLA-RVL |

Implements automated correlation and review of audit records (AU-6) and
monitoring for indicators of attack (SI-4). It relies on AU-2 and AU-12
rather than providing them: the events it reads must be selected for
logging and generated by the trail
([`org-cloudtrail`](../org-cloudtrail/)), which step 1 above checks.
Detective only: a human still decides whether the credential is stolen
and what to revoke.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| cloudtrail_log_group_name | Name of the CloudWatch Logs log group receiving CloudTrail management events (the log_group_name output of modules/org-cloudtrail). It must be in the account and region this module is deployed in. | `string` | n/a | yes |
| code_signing_config_arn | Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip. | `string` | `null` | no |
| denied_call_threshold | Denied API calls (errorCode AccessDenied* or *UnauthorizedOperation) by one principal inside the window that make it a suspect. A suspect that also read a secret or parameter is reported. | `number` | `20` | no |
| enabled | Run the detector on its schedule. Default false: everything is created but the EventBridge rule is DISABLED, so nothing is queried and nothing alerts. Turn it on per account after a tuning period. | `bool` | `false` | no |
| ignored_principal_arns | CloudTrail principal ARNs (userIdentity.arn) never reported, for automation that is routinely denied and also reads secrets, e.g. "arn:<partition>:sts::<account>:assumed-role/inventory-scanner/*". "*" matches any run of characters. Keep the list short: an ignored principal whose credential is stolen is not detected. | `list(string)` | `[]` | no |
| name_prefix | Prefix used for naming all resources created by this module. | `string` | `"secret-access-burst-detector"` | no |
| notification_email | Optional email address to subscribe to the SNS topic. Leave empty to skip. | `string` | `""` | no |
| query_window_minutes | How far back each run looks. Denied calls and secret reads are correlated inside this window. A burst and a read are reliably seen together only when they are no further apart than this window minus the schedule interval minus the CloudTrail delivery delay (about 5 minutes): 40 minutes with the defaults. Keep it larger than the schedule interval. A longer window scans more log data per run. | `number` | `60` | no |
| reserved_concurrent_executions | Concurrency reserved for the Lambda. Set -1 to reserve none: accounts at the 10-execution quota floor (new and sandbox accounts) reject any reservation. 0 is rejected because it throttles every run. | `number` | `2` | no |
| schedule_expression | EventBridge schedule expression controlling how often the detector runs. Keep the interval well below query_window_minutes: see that variable for the span that is reliably covered. | `string` | `"rate(15 minutes)"` | no |
| use_fips_endpoint | Make the Lambda's AWS SDK calls through FIPS 140 validated endpoints (sets AWS_USE_FIPS_ENDPOINT). Default true, matching the provider setting in this library's root configurations. | `bool` | `true` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| lambda_function_arn | ARN of the detector Lambda function. |
| sns_topic_arn | ARN of the SNS topic findings and failure alarms are sent to. |
<!-- END_TF_DOCS -->

## Notes

- Tested with plan-only `terraform test` runs and mocked unit tests. The
  two query strings have not been run against a live CloudTrail log
  group from this repository; step 2 above is where you confirm them.
- CloudTrail usually delivers an event to CloudWatch Logs within about
  5 minutes. The overlapping windows cover that delay, at the cost of
  that much of the reliably covered span (`query_window_minutes` minus
  the schedule interval minus the delay).
- `ignored_principal_arns` is passed to the Lambda as an environment
  variable, and Lambda limits all of a function's variables to 4 KB.
