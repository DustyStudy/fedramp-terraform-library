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
| AC-3, SC-7, SC-8, SC-13 | KSI-CNBC-02 |

## Notes

- **Read this before assuming "FIPS module" means "FIPS everywhere."**
  Only `kms`, `ec2`, and `sts` (`fips_endpoint_services`) have a genuine,
  separate FIPS-suffixed VPC endpoint service name
  (`com.amazonaws.<region>.kms-fips`, etc.) as of this writing. Everything
  in `standard_endpoint_services` (`secretsmanager`, `ssm`, `logs`, and
  others used for typical SSM/Session-Manager connectivity) does **not**
  have a distinct FIPS endpoint — where AWS offers FIPS access to those
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
