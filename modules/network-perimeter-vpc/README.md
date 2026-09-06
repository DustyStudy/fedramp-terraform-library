# network-perimeter-vpc

A 3-tier VPC (public, application, database) across two Availability
Zones, with Flow Logs for all traffic delivered to a KMS-encrypted
CloudWatch Logs group, and the VPC's default security group stripped to
zero rules.

## Usage

```hcl
module "network_perimeter_vpc" {
  source              = "../../modules/network-perimeter-vpc"
  environment         = "prod"
  vpc_cidr            = "10.100.0.0/16"
  availability_zones  = ["us-east-1a", "us-east-1b"]
  public_subnet_cidrs = ["10.100.1.0/24", "10.100.2.0/24"]
  app_subnet_cidrs    = ["10.100.10.0/24", "10.100.20.0/24"]
  db_subnet_cidrs     = ["10.100.100.0/24", "10.100.200.0/24"]
  log_retention_days  = 365
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AU-12, SC-7, CM-7 | KSI-CNBC-02, KSI-MLA-01 |

## Notes

- This module provisions the VPC, subnets, Flow Logs, and default-SG
  lockdown only — it does **not** create route tables, NAT gateways,
  internet gateways, or subnet-route associations. Wire those up
  separately based on which tiers actually need egress (typically just
  the application tier, via NAT in the public tier).
- `map_public_ip_on_launch = false` on the public subnets is intentional —
  "public" here means internet-routable via an IGW you attach, not
  "auto-assigns public IPs." Assign EIPs explicitly to anything that
  actually needs a public address.
- All variable defaults (CIDRs, AZs) are illustrative for a two-AZ
  `us-east-1` deployment — override every one of them for a real
  environment; the defaults exist so the module is directly runnable in a
  sandbox, not as a recommended production layout.
