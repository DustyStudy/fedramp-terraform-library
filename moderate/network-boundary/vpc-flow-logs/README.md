# vpc-flow-logs

Enables VPC Flow Logs (all traffic) delivered to an encrypted,
access-logged S3 bucket, for an existing VPC.

## Usage

```hcl
module "vpc_flow_logs" {
  source = "../../moderate/network-boundary/vpc-flow-logs"
  vpc_id = "vpc-xxxxxxxxxxxxxxxxx"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| SC-7, AU-2, AU-12 | KSI-CNBC-02, KSI-MLA-01 |

## Notes

If you created your VPC through `modules/network-perimeter-vpc`, that
module already includes Flow Logs (to CloudWatch Logs) — you don't need
this module too. Use this one for a VPC that already exists outside that
module, or specifically if you want an S3 destination instead of
CloudWatch Logs.
