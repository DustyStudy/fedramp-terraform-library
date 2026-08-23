# logging-monitoring

CloudWatch Logs metric filters and alarms for the 14 detections in the CIS
AWS Foundations Benchmark (mirrored as AWS Security Hub CSPM controls
CloudWatch.1 through CloudWatch.14). All 14 filter patterns are copied
verbatim from AWS's Security Hub CSPM documentation — the corresponding
checks fail if the exact prescribed pattern isn't used, so none of these
are paraphrased.

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
| Root account usage | AC-6(5), AU-6 | KSI-IAM-02, KSI-MLA-01 |
| Unauthorized API calls | AU-6, SI-4 | KSI-MLA-04 |
| Console sign-in without MFA | IA-2(1), AU-6 | KSI-IAM-01 |
| IAM policy changes | AC-6, AU-6 | KSI-IAM-03 |
| CloudTrail config changes | AU-12, AU-6 | KSI-MLA-01 |
| Console auth failures | AU-6, SI-4 | KSI-MLA-04 |
| CMK disable/scheduled deletion | SC-12, SC-28 | KSI-CNBC-02 |
| S3 bucket policy changes | AC-3, AU-6 | KSI-CNBC-01 |
| Config configuration changes | CM-6, AU-6 | KSI-CNBC-01 |
| Security group changes | CM-6, SC-7 | KSI-CNBC-02 |
| NACL changes | CM-6, SC-7 | KSI-CNBC-02 |
| Network gateway changes | SC-7, AU-6 | KSI-CNBC-02 |
| Route table changes | SC-7, AU-6 | KSI-CNBC-02 |
| VPC changes | SC-7, CM-6 | KSI-CNBC-02 |
