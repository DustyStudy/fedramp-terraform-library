# waf-hardened

A regional (or CloudFront-scoped) WAFv2 Web ACL with three AWS-managed
rule groups (Common Rule Set, Known Bad Inputs, Amazon IP Reputation
List), a rate-based rule for DoS mitigation, and KMS-encrypted logging to
CloudWatch Logs.

## Usage

```hcl
module "waf_hardened" {
  source                = "../../modules/waf-hardened"
  environment           = "prod"
  scope                 = "REGIONAL"
  rate_limit_threshold  = 2000
  log_retention_days    = 365
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| SC-5, SI-3, AU-2 | KSI-CNBC-02 |

## Notes

- This module creates the Web ACL and its logging configuration only —
  associate it with an ALB, API Gateway, or CloudFront distribution
  separately via `aws_wafv2_web_acl_association` (or the CloudFront
  distribution's `web_acl_id` argument), using `web_acl_arn` from this
  module's outputs.
- If you set `scope = "CLOUDFRONT"`, the Web ACL, its KMS key, and its
  CloudWatch Logs group must all be created in `us-east-1` regardless of
  where the rest of your stack lives — that's a WAFv2/CloudFront
  requirement, not something this module enforces for you.
- The CloudWatch Logs group name (`aws-waf-logs-${var.environment}`) is
  intentionally prefixed `aws-waf-logs-` — WAFv2 logging configuration
  requires that exact prefix on the destination log group, or log
  delivery fails silently.
- `rate_limit_threshold` (default 2000) is requests per 5-minute window
  per source IP — tune it against your actual traffic patterns before
  relying on the default in production; too low blocks legitimate bursty
  traffic, too high defeats the point of the rule.
