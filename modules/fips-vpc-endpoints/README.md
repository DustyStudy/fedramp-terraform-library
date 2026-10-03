# fips-vpc-endpoints

VPC interface endpoints, split into two groups depending on whether AWS
actually publishes a distinct FIPS-suffixed service name for that
service, plus a Gateway endpoint for S3.

## Usage

```hcl
module "fips_vpc_endpoints" {
  source          = "../../modules/fips-vpc-endpoints"
  vpc_id          = var.vpc_id
  vpc_cidr        = var.vpc_cidr
  subnet_ids      = var.private_subnet_ids
  route_table_ids = var.private_route_table_ids
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-3, SC-7, SC-8, SC-13 | KSI-CNA-RNT, KSI-SVC-VCM |

## Notes

- **Read this before assuming "FIPS module" means "FIPS everywhere."**
  By default the module creates FIPS-suffixed endpoints for `kms`, `ec2`,
  and `sts` (`fips_endpoint_services`). AWS publishes many more `-fips`
  VPC endpoint service names (e.g. `s3-fips`, `sqs-fips`, `dynamodb-fips`,
  `rds-fips`; see the [PrivateLink list](https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-privatelink-support.html)); add the ones your
  workload uses. Everything in `standard_endpoint_services`
  (`secretsmanager`, `ssm`, `logs`, and others used for typical
  SSM/Session-Manager connectivity) does **not** have a distinct FIPS
  endpoint — where AWS offers FIPS access to those
  services at all, it's through an alternate FIPS-labeled DNS hostname on
  the *same* ordinary endpoint, which is a client/SDK configuration
  choice, not separate infrastructure this module creates.
- Both variable defaults are verified against AWS's PrivateLink service
  list, not assumed — re-check that list before adding new entries, since
  it changes over time. See the long-form comments in `variables.tf`.
- Don't treat deploying this module as satisfying a FIPS-validated-crypto
  requirement on its own — verify the calling application is actually
  requesting the FIPS hostname where that matters for your compliance
  boundary.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| route_table_ids | Route table IDs for S3 Gateway Endpoint | `list(string)` | n/a | yes |
| subnet_ids | Subnet IDs for Interface Endpoints (must be private/isolated) | `list(string)` | n/a | yes |
| vpc_cidr | VPC CIDR block allowed to communicate with endpoints | `string` | n/a | yes |
| vpc_id | VPC ID where endpoints will be provisioned | `string` | n/a | yes |
| environment | Deployment environment name | `string` | `"fedramp"` | no |
| fips_endpoint_services | FIPS-suffixed VPC endpoint services to create (e.g. 'kms-fips' resolves to com.amazonaws.<region>.kms-fips). The default covers kms, ec2 and sts. AWS publishes many more -fips service names (s3-fips, sqs-fips, dynamodb-fips, rds-fips, ebs-fips, ...) — add any your workload uses, after confirming availability in your region: https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-privatelink-support.html | `list(string)` | ```[ "kms-fips", "ec2-fips", "sts-fips" ]``` | no |
| standard_endpoint_services | List of AWS services needed for typical SSM/Session-Manager-based connectivity that do NOT have a distinct FIPS-suffixed VPC endpoint service name as of this writing (confirmed against AWS's PrivateLink service list). Where AWS does offer FIPS access to these services, it works through an alternate FIPS-labeled private DNS hostname on this SAME endpoint (e.g. monitoring-fips.<region>.amazonaws.com resolving through the ordinary 'monitoring' endpoint) — that's an application/ SDK-level configuration choice (which hostname your client requests), not a separate piece of infrastructure this module can create. Don't assume these endpoints provide FIPS-validated cryptography just because they're deployed as part of a "FIPS" module — verify your application is actually requesting the FIPS hostname if that matters for your compliance boundary. | `list(string)` | ```[ "secretsmanager", "ssm", "ssmmessages", "ec2messages", "ecr.api", "ecr.dkr", "logs", "monitoring" ]``` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| endpoint_security_group_id | n/a |
| fips_endpoint_ids | Endpoint IDs for services with a dedicated FIPS-suffixed VPC endpoint service name |
| standard_endpoint_ids | Endpoint IDs for services without a distinct FIPS-suffixed service name (see variables.tf note) |
<!-- END_TF_DOCS -->
