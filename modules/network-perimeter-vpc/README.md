# network-perimeter-vpc

A 3-tier VPC (public, application, database), one subnet per CIDR per
Availability Zone, with:

- Flow Logs for all traffic delivered to a KMS-encrypted CloudWatch Logs
  group, and the VPC's default security group stripped to zero rules.
- A route table per tier (one per subnet for the application tier), each
  explicitly associated, so the tiers no longer share the VPC's main route
  table.
- A network ACL on the database tier that admits only the application-tier
  CIDRs on `database_port`.
- Opt-in: an internet gateway for the public tier, NAT gateways for
  application-tier egress, and a Route 53 Resolver DNS Firewall that blocks
  lookups of known command-and-control relay domains.

## Usage

```hcl
module "network_perimeter_vpc" {
  source              = "../../modules/network-perimeter-vpc"
  environment         = "prod"
  vpc_cidr            = "10.100.0.0/16"
  public_subnet_cidrs = ["10.100.1.0/24", "10.100.2.0/24"]
  app_subnet_cidrs    = ["10.100.10.0/24", "10.100.20.0/24"]
  db_subnet_cidrs     = ["10.100.100.0/24", "10.100.200.0/24"]
  database_port       = 5432
  log_retention_days  = 365
  enable_dns_firewall = true

  # Egress account only: the library's org SCP denies internet gateways
  # everywhere else.
  # enable_internet_gateway = true
  # nat_gateway_mode        = "per_az"
}

module "fips_vpc_endpoints" {
  source     = "../../modules/fips-vpc-endpoints"
  vpc_id     = module.network_perimeter_vpc.vpc_id
  subnet_ids = module.network_perimeter_vpc.application_subnet_ids
  # Not the VPC's main route table: no subnet uses it any more.
  route_table_ids = module.network_perimeter_vpc.application_route_table_ids
  # ...
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AU-12, SC-7, CM-7, SI-4 | KSI-CNA-RNT, KSI-CNA-ULN, KSI-MLA-LET |

## Notes

- `availability_zones` defaults to the region's available zones in name
  order (Local and Wavelength Zones excluded), so the defaults work in
  GovCloud and any other region. Subnet N of each tier goes in zone N; a
  CIDR list longer than the zone list fails the plan with a clear message.
  Pin `availability_zones` if you need specific zones: a zone inserted
  earlier in the list would move subnets, which replaces them.
- Routing by tier:

  | Tier | Route table | Routes the module adds |
  |---|---|---|
  | public | one, `public_route_table_id` | `0.0.0.0/0` to the internet gateway when `enable_internet_gateway = true` |
  | application | one per subnet, `application_route_table_ids` | `0.0.0.0/0` to a NAT gateway when `nat_gateway_mode` is `single` or `per_az` |
  | database | one, `database_route_table_id` | none, in any configuration |

  With the defaults every table has only the VPC-local route. In a
  hub-and-spoke network, add your own Transit Gateway routes to the
  application tables through the outputs instead of turning on the
  internet gateway.
- `enable_internet_gateway` is off by default because the library's org
  SCP denies internet gateways outside the egress account. Turn it on only
  in an account that SCP exempts.
- `nat_gateway_mode = "single"` puts one NAT gateway in the first public
  subnet and is cheaper; `"per_az"` puts one in every public subnet so
  losing a zone does not cut egress for the others. Both need
  `enable_internet_gateway = true`. Application subnet N uses the NAT
  gateway in public subnet N, so keep the two CIDR lists the same length
  for `per_az`.
- The database network ACL (`enable_database_nacl`, on by default) allows
  inbound TCP on `database_port` from each application-tier CIDR and
  outbound TCP 1024-65535 back to them, and nothing else. Network ACLs are
  stateless, so the database tier cannot open connections of its own:
  that includes reaching interface VPC endpoints in the application tier,
  an S3 gateway endpoint, or a database subnet in another zone. Set
  `enable_database_nacl = false` and bring your own ACL if you need any of
  those, or if a bastion, peered VPC or the public tier must reach the
  databases. Security groups are still required; the ACL is a second layer.
- `map_public_ip_on_launch = false` on the public subnets is intentional —
  "public" here means internet-routable via the internet gateway, not
  "auto-assigns public IPs." Assign EIPs explicitly to anything that
  actually needs a public address.
- The CIDR defaults are illustrative; override them for a real
  environment.
- `enable_dns_firewall` (off by default) answers NXDOMAIN for
  `dns_firewall_blocked_domains` when an instance asks the VPC's Route 53
  Resolver. The default list is GSocket's relay network
  (`[a-z].gs.thc.org`) and download hosts (`gsocket.io`), which attackers
  have used to keep access to Linux web servers after the flaw they came
  in through was patched. It does not stop an implant that connects by IP
  address (`GSOCKET_IP`), runs its own relay (`GSOCKET_DOMAIN`), or
  resolves names through DNS over HTTPS or a resolver outside the VPC, and
  it does not log blocked lookups unless Resolver query logging is turned
  on separately. Finding the blocked lookup is the cue to look for the
  implant; blocking it is not cleanup.
- The DNS Firewall association has mutation protection on
  (`dns_firewall_mutation_protection`), and AWS refuses to remove a
  protected association. To turn the firewall off or destroy the module,
  apply once with `dns_firewall_mutation_protection = false`, then apply
  the removal.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| app_subnet_cidrs | n/a | `list(string)` | ```[ "10.100.10.0/24", "10.100.20.0/24" ]``` | no |
| availability_zones | Availability Zones for the subnets; subnet N of each tier goes in zone N. Null uses the region's available zones in name order. No subnet CIDR list may be longer than this list. | `list(string)` | `null` | no |
| database_port | TCP port the database-tier network ACL allows from the application tier (5432 PostgreSQL, 3306 MySQL, 1433 SQL Server). | `number` | `5432` | no |
| db_subnet_cidrs | n/a | `list(string)` | ```[ "10.100.100.0/24", "10.100.200.0/24" ]``` | no |
| dns_firewall_blocked_domains | Domains the DNS Firewall answers with NXDOMAIN. A leading *. matches subdomains only, so list the apex too. The default is GSocket's relay network ([a-z].gs.thc.org) and its download hosts (gsocket.io). | `list(string)` | ```[ "gs.thc.org", "*.gs.thc.org", "gsocket.io", "*.gsocket.io" ]``` | no |
| dns_firewall_mutation_protection | Stop the DNS Firewall association from being changed or removed. AWS refuses to remove a protected association, so to turn the firewall off or destroy the module, apply with this set to false first. | `bool` | `true` | no |
| enable_database_nacl | Put the database subnets behind a network ACL that allows only the application-tier CIDRs on database_port, plus return traffic. Set false if something outside the application tier must reach the database tier, or the database tier must open connections itself. | `bool` | `true` | no |
| enable_dns_firewall | Attach a Route 53 Resolver DNS Firewall rule group to the VPC that blocks dns_firewall_blocked_domains. | `bool` | `false` | no |
| enable_internet_gateway | Attach an internet gateway and give the public tier a default route to it. Off by default: the library's org SCP denies internet gateways outside the egress account. | `bool` | `false` | no |
| environment | n/a | `string` | `"fedramp"` | no |
| log_retention_days | n/a | `number` | `365` | no |
| nat_gateway_mode | NAT for application-tier egress: "none", "single" (one gateway in the first public subnet, shared by every application subnet) or "per_az" (one per public subnet, so losing a zone does not cut egress for the others). Anything but "none" needs enable_internet_gateway = true. | `string` | `"none"` | no |
| public_subnet_cidrs | n/a | `list(string)` | ```[ "10.100.1.0/24", "10.100.2.0/24" ]``` | no |
| vpc_cidr | n/a | `string` | `"10.100.0.0/16"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| application_route_table_ids | IDs of the application tier's route tables, one per application subnet, in subnet order. |
| application_subnet_ids | n/a |
| database_route_table_id | ID of the database tier's route table. The module never adds a route to it. |
| database_subnet_ids | n/a |
| dns_firewall_rule_group_id | ID of the DNS Firewall rule group, or null when enable_dns_firewall is false. |
| public_route_table_id | ID of the public tier's route table. |
| public_subnet_ids | n/a |
| vpc_id | n/a |
<!-- END_TF_DOCS -->
