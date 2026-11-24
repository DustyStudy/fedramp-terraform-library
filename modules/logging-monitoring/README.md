# logging-monitoring

CloudWatch Logs metric filters and alarms for the 14 detections in the CIS
AWS Foundations Benchmark (mirrored as AWS Security Hub CSPM controls
CloudWatch.1 through CloudWatch.14). Those 14 filter patterns are copied
verbatim from AWS's Security Hub CSPM documentation — the corresponding
checks fail if the exact prescribed pattern isn't used, so none of these
are paraphrased. On top of the CIS 14 the module adds two MFA-change alarms
(IAM and IAM Identity Center) and an optional unexpected-secret-read alarm.

## Usage

```hcl
module "logging_monitoring" {
  source                    = "../../moderate/logging-monitoring"
  cloudtrail_log_group_name = module.org_cloudtrail.log_group_name
}
```

## Control mapping

| Alarm | Rev5 Controls | 20x KSI |
|---|---|---|
| Root account usage | AC-6(5), AU-6 | KSI-IAM-SUS, KSI-MLA-RVL |
| Unauthorized API calls | AU-6, SI-4 | KSI-MLA-RVL |
| Console sign-in without MFA | IA-2(1), AU-6 | KSI-IAM-APM |
| IAM policy changes | AC-6, AU-6 | KSI-IAM-JIT |
| CloudTrail config changes | AU-12, AU-6 | KSI-MLA-LET |
| Console auth failures | AU-6, SI-4 | KSI-IAM-SUS |
| CMK disable/scheduled deletion | SC-12, SC-28 | KSI-SVC-ASM |
| S3 bucket policy changes | AC-3, AU-6 | KSI-SVC-ACM |
| Config configuration changes | CM-6, AU-6 | KSI-SVC-ACM |
| Security group changes | CM-6, SC-7 | KSI-CNA-ULN |
| NACL changes | CM-6, SC-7 | KSI-CNA-ULN |
| Network gateway changes | SC-7, AU-6 | KSI-CNA-RNT |
| Route table changes | SC-7, AU-6 | KSI-CNA-ULN |
| VPC changes | SC-7, CM-6 | KSI-CNA-RNT |
| MFA device changes (not CIS) | IA-2(1), IA-5, AU-6 | KSI-IAM-MFA |
| Identity Center MFA and passkey changes (not CIS) | IA-2(1), IA-5, AU-6 | KSI-IAM-MFA |
| Unexpected secret reads (not CIS; needs `expected_secret_readers`) | AC-6, AU-6, SI-4 | KSI-MLA-RVL |

The last three alarms go beyond the CIS 14. The secret-read alarm exists only
when `expected_secret_readers` is non-empty (alerting on every read is too
noisy); it covers Secrets Manager `GetSecretValue` and SSM `GetParameter`,
`GetParameters`, `GetParametersByPath` and `GetParameterHistory`. List roles
as `arn:<partition>:sts::<account>:assumed-role/<RoleName>/*` (IAM role ARNs
are rejected because they never match a session), and keep the list short:
the generated pattern must fit the 1024-character filter limit, checked at
plan. The Identity Center alarm matches any non-read event from the
`sso-directory` and `identitystore` sources whose name contains `Mfa` or
`WebAuthn`: AWS documents those sources for MFA device management but lists no
event names, so confirm the match against your own CloudTrail the first time a
user registers a device.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| cloudtrail_log_group_name | Name of the CloudWatch Logs log group receiving CloudTrail management events (the log_group_name output of modules/org-cloudtrail). | `string` | n/a | yes |
| expected_secret_readers | CloudTrail principal ARNs (userIdentity.arn) that normally read secrets and parameters, e.g. "arn:<partition>:sts::<account>:assumed-role/app-role/*". Each entry may contain one "*" wildcard. For a role, use that assumed-role session form, not the IAM role ARN, which never appears in userIdentity.arn. When non-empty, the module alarms on secretsmanager GetSecretValue and ssm GetParameter, GetParameters, GetParametersByPath and GetParameterHistory by any other principal. The generated filter pattern must fit CloudWatch Logs' 1024-character limit, so prefer wildcards over long lists. Default empty creates no secret-read filter or alarm, because alerting on every read is too noisy. | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| cis_alarms_topic_arn | SNS topic receiving all CIS/Security Hub CloudWatch alarms plus the MFA and secret-read alarms — subscribe your on-call, ticketing, or SOAR integration here. |
<!-- END_TF_DOCS -->
