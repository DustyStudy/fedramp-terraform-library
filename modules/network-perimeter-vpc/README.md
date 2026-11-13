# network-perimeter-vpc

A 3-tier VPC (public, application, database) across two Availability
Zones, with Flow Logs for all traffic delivered to a KMS-encrypted
CloudWatch Logs group, and the VPC's default security group stripped to
zero rules. Optionally, a Route 53 Resolver DNS Firewall blocks lookups
of known command-and-control relay domains.

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
  enable_dns_firewall = true
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AU-12, SC-7, CM-7, SI-4 | KSI-CNA-RNT, KSI-CNA-ULN, KSI-MLA-LET |

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
| availability_zones | n/a | `list(string)` | ```[ "us-east-1a", "us-east-1b" ]``` | no |
| db_subnet_cidrs | n/a | `list(string)` | ```[ "10.100.100.0/24", "10.100.200.0/24" ]``` | no |
| dns_firewall_blocked_domains | Domains the DNS Firewall answers with NXDOMAIN. A leading *. matches subdomains only, so list the apex too. The default is GSocket's relay network ([a-z].gs.thc.org) and its download hosts (gsocket.io). | `list(string)` | ```[ "gs.thc.org", "*.gs.thc.org", "gsocket.io", "*.gsocket.io" ]``` | no |
| dns_firewall_mutation_protection | Stop the DNS Firewall association from being changed or removed. AWS refuses to remove a protected association, so to turn the firewall off or destroy the module, apply with this set to false first. | `bool` | `true` | no |
| enable_dns_firewall | Attach a Route 53 Resolver DNS Firewall rule group to the VPC that blocks dns_firewall_blocked_domains. | `bool` | `false` | no |
| environment | n/a | `string` | `"fedramp"` | no |
| log_retention_days | n/a | `number` | `365` | no |
| public_subnet_cidrs | n/a | `list(string)` | ```[ "10.100.1.0/24", "10.100.2.0/24" ]``` | no |
| vpc_cidr | n/a | `string` | `"10.100.0.0/16"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| application_subnet_ids | n/a |
| database_subnet_ids | n/a |
| dns_firewall_rule_group_id | ID of the DNS Firewall rule group, or null when enable_dns_firewall is false. |
| public_subnet_ids | n/a |
| vpc_id | n/a |
<!-- END_TF_DOCS -->
