# Plan-only tests. Dummy credentials plus overridden identity data keep the
# real AWS provider from calling AWS.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = data.aws_caller_identity.current
  values = {
    account_id = "123456789012"
  }
}

override_data {
  target = data.aws_region.current
  values = {
    name = "us-gov-west-1"
  }
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws-us-gov"
  }
}

override_resource {
  target          = aws_kms_key.flow_logs
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/flow"
  }
}

override_resource {
  target          = aws_cloudwatch_log_group.flow_logs
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/vpc-flow-logs/fedramp"
  }
}

override_resource {
  target          = aws_iam_role.flow_logs
  override_during = plan
  values = {
    arn = "arn:aws-us-gov:iam::123456789012:role/fedramp-vpc-flow-logs-role"
  }
}

override_resource {
  target          = aws_vpc.this
  override_during = plan
  values = {
    id = "vpc-0aaaaaaaaaaaaaaa1"
  }
}

override_resource {
  target          = aws_route_table.public
  override_during = plan
  values = {
    id = "rtb-public"
  }
}

override_resource {
  target          = aws_route_table.application
  override_during = plan
  values = {
    id = "rtb-app"
  }
}

override_resource {
  target          = aws_route_table.database
  override_during = plan
  values = {
    id = "rtb-db"
  }
}

variables {
  availability_zones = ["us-gov-west-1a", "us-gov-west-1b"]
}

run "flow_logs_capture_all_traffic" {
  command = plan

  assert {
    condition     = aws_flow_log.this.traffic_type == "ALL" && aws_flow_log.this.max_aggregation_interval == 60
    error_message = "VPC flow logs must capture accepted and rejected traffic at one-minute aggregation (AU-12, SI-4)."
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow_logs.retention_in_days >= 365
    error_message = "Flow logs must be kept at least 365 days by default (AU-11)."
  }
}

run "default_security_group_is_closed" {
  command = plan

  assert {
    condition     = length(aws_default_security_group.default.ingress) == 0 && length(aws_default_security_group.default.egress) == 0
    error_message = "The default security group must have no rules (SC-7, CIS 5.4)."
  }
}

run "subnets_do_not_assign_public_ips" {
  command = plan

  assert {
    condition     = alltrue([for s in concat(aws_subnet.public, aws_subnet.application, aws_subnet.database) : !s.map_public_ip_on_launch])
    error_message = "No subnet may assign public IPs on launch (SC-7)."
  }

  assert {
    condition     = length(aws_subnet.public) == 2 && length(aws_subnet.application) == 2 && length(aws_subnet.database) == 2
    error_message = "The VPC must get one subnet per tier per CIDR given."
  }

  assert {
    condition     = [for s in aws_subnet.database : s.availability_zone] == ["us-gov-west-1a", "us-gov-west-1b"]
    error_message = "Subnets must be spread across the given availability zones."
  }
}

run "flow_logs_role_is_scoped" {
  command = plan

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.flow_logs_assume.json).Statement).Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "Only this account's flow logs may assume the role (confused deputy)."
  }

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.flow_logs_assume.json).Statement).Condition.ArnLike["aws:SourceArn"] == "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:vpc-flow-log/*"
    error_message = "The role's source ARN condition must be built from the current partition and region."
  }

  assert {
    condition     = aws_kms_key.flow_logs.enable_key_rotation && aws_kms_key.flow_logs.deletion_window_in_days >= 7 && aws_kms_key.flow_logs.deletion_window_in_days <= 30
    error_message = "The flow log CMK must rotate and keep a 7 to 30 day deletion window (SC-12)."
  }
}

run "flow_log_is_wired_up" {
  command = plan

  assert {
    condition     = aws_flow_log.this.vpc_id == "vpc-0aaaaaaaaaaaaaaa1" && aws_flow_log.this.log_destination == "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/vpc-flow-logs/fedramp" && aws_flow_log.this.iam_role_arn == "arn:aws-us-gov:iam::123456789012:role/fedramp-vpc-flow-logs-role"
    error_message = "The flow log must cover the module's VPC and write to its log group with its role."
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow_logs.kms_key_id == "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/flow" && aws_default_security_group.default.vpc_id == "vpc-0aaaaaaaaaaaaaaa1"
    error_message = "Flow logs must use the module's CMK, and the closed default security group must be the module VPC's."
  }
}

run "dns_firewall_is_off_by_default" {
  command = plan

  assert {
    condition     = length(aws_route53_resolver_firewall_rule_group_association.this) == 0 && output.dns_firewall_rule_group_id == null
    error_message = "The DNS Firewall must be opt-in."
  }
}

run "dns_firewall_blocks_gsocket_relays" {
  command = plan

  variables {
    enable_dns_firewall = true
  }

  override_resource {
    target          = aws_route53_resolver_firewall_rule_group.this
    override_during = plan
    values = {
      id = "rslvr-frg-0aaaaaaaaaaaaaaa1"
    }
  }

  override_resource {
    target          = aws_route53_resolver_firewall_domain_list.blocked
    override_during = plan
    values = {
      id = "rslvr-fdl-0aaaaaaaaaaaaaaa1"
    }
  }

  assert {
    condition     = alltrue([for d in ["gs.thc.org", "*.gs.thc.org", "gsocket.io", "*.gsocket.io"] : contains(aws_route53_resolver_firewall_domain_list.blocked[0].domains, d)])
    error_message = "The default list must block GSocket's relay apex and subdomains and its download hosts."
  }

  assert {
    condition     = aws_route53_resolver_firewall_rule.block[0].action == "BLOCK" && aws_route53_resolver_firewall_rule.block[0].block_response == "NXDOMAIN" && aws_route53_resolver_firewall_rule.block[0].firewall_domain_list_id == "rslvr-fdl-0aaaaaaaaaaaaaaa1" && aws_route53_resolver_firewall_rule.block[0].firewall_rule_group_id == "rslvr-frg-0aaaaaaaaaaaaaaa1"
    error_message = "The rule must block the module's domain list inside the module's rule group (SC-7)."
  }

  assert {
    condition     = aws_route53_resolver_firewall_rule_group_association.this[0].vpc_id == "vpc-0aaaaaaaaaaaaaaa1" && aws_route53_resolver_firewall_rule_group_association.this[0].firewall_rule_group_id == "rslvr-frg-0aaaaaaaaaaaaaaa1" && aws_route53_resolver_firewall_rule_group_association.this[0].mutation_protection == "ENABLED"
    error_message = "The rule group must be attached to the module's VPC with mutation protection on."
  }
}

run "dns_firewall_rejects_empty_list" {
  command = plan

  variables {
    enable_dns_firewall          = true
    dns_firewall_blocked_domains = []
  }

  expect_failures = [var.dns_firewall_blocked_domains]
}

run "dns_firewall_protection_can_be_lifted_for_teardown" {
  command = plan

  variables {
    enable_dns_firewall              = true
    dns_firewall_mutation_protection = false
  }

  assert {
    condition     = aws_route53_resolver_firewall_rule_group_association.this[0].mutation_protection == "DISABLED"
    error_message = "Turning off mutation protection must reach the association so it can be removed."
  }
}

run "availability_zones_fall_back_to_the_region" {
  command = plan

  variables {
    availability_zones = null
  }

  override_data {
    target = data.aws_availability_zones.available
    values = {
      names = ["us-gov-east-1a", "us-gov-east-1b", "us-gov-east-1c"]
    }
  }

  assert {
    condition     = alltrue([for tier in [aws_subnet.public, aws_subnet.application, aws_subnet.database] : [for s in tier : s.availability_zone] == ["us-gov-east-1a", "us-gov-east-1b"]])
    error_message = "With availability_zones unset, subnets must use the region's available zones in order, not us-east-1 names."
  }
}

run "explicit_availability_zones_skip_the_lookup" {
  command = plan

  assert {
    condition     = length(data.aws_availability_zones.available) == 0
    error_message = "Explicit availability_zones must not need ec2:DescribeAvailabilityZones."
  }
}

run "more_cidrs_than_zones_is_rejected" {
  command = plan

  variables {
    db_subnet_cidrs = ["10.100.100.0/24", "10.100.200.0/24", "10.100.201.0/24"]
  }

  expect_failures = [aws_vpc.this]
}

run "internet_and_nat_gateways_are_off_by_default" {
  command = plan

  assert {
    condition     = length(aws_internet_gateway.this) == 0 && length(aws_route.public_internet) == 0
    error_message = "The internet gateway must be opt-in: the org SCP denies it outside the egress account."
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 0 && length(aws_eip.nat) == 0 && length(aws_route.application_nat) == 0
    error_message = "NAT gateways must be opt-in."
  }
}

run "each_tier_has_its_own_route_table" {
  command = plan

  assert {
    condition     = length(aws_route_table_association.public) == 2 && alltrue([for a in aws_route_table_association.public : a.route_table_id == "rtb-public"])
    error_message = "Every public subnet must be associated with the public route table."
  }

  assert {
    condition     = length(aws_route_table.application) == 2 && length(aws_route_table_association.application) == 2 && alltrue([for a in aws_route_table_association.application : a.route_table_id == "rtb-app"])
    error_message = "Every application subnet must get its own application route table."
  }

  assert {
    condition     = length(aws_route_table_association.database) == 2 && alltrue([for a in aws_route_table_association.database : a.route_table_id == "rtb-db"])
    error_message = "Every database subnet must be associated with the database route table."
  }

  assert {
    condition     = output.public_route_table_id == "rtb-public" && output.application_route_table_ids == ["rtb-app", "rtb-app"] && output.database_route_table_id == "rtb-db"
    error_message = "Route table IDs must be output per tier (for fips-vpc-endpoints route_table_ids)."
  }
}

run "database_nacl_allows_only_the_application_tier" {
  command = plan

  variables {
    database_port = 3306
  }

  assert {
    condition     = sort([for r in aws_network_acl.database[0].ingress : "${r.action} ${r.protocol} ${r.cidr_block} ${r.from_port}-${r.to_port}"]) == tolist(["allow tcp 10.100.10.0/24 3306-3306", "allow tcp 10.100.20.0/24 3306-3306"])
    error_message = "The database NACL must admit only the application-tier CIDRs on database_port (SC-7)."
  }

  assert {
    condition     = sort([for r in aws_network_acl.database[0].egress : "${r.action} ${r.protocol} ${r.cidr_block} ${r.from_port}-${r.to_port}"]) == tolist(["allow tcp 10.100.10.0/24 1024-65535", "allow tcp 10.100.20.0/24 1024-65535"])
    error_message = "The database NACL must send only ephemeral-port return traffic, and only to the application tier."
  }

  assert {
    condition     = aws_network_acl.database[0].vpc_id == "vpc-0aaaaaaaaaaaaaaa1"
    error_message = "The database NACL must belong to the module's VPC."
  }
}

run "database_nacl_can_be_turned_off" {
  command = plan

  variables {
    enable_database_nacl = false
  }

  assert {
    condition     = length(aws_network_acl.database) == 0
    error_message = "enable_database_nacl = false must leave the database subnets on the VPC's default NACL."
  }
}

run "internet_gateway_routes_only_the_public_tier" {
  command = plan

  variables {
    enable_internet_gateway = true
  }

  assert {
    condition     = length(aws_internet_gateway.this) == 1 && aws_route.public_internet[0].route_table_id == "rtb-public" && aws_route.public_internet[0].destination_cidr_block == "0.0.0.0/0"
    error_message = "The internet gateway's default route must go in the public route table only."
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 0 && length(aws_route.application_nat) == 0
    error_message = "An internet gateway alone must not create NAT gateways or application-tier routes."
  }
}

run "single_nat_gateway_serves_every_application_subnet" {
  command = plan

  variables {
    enable_internet_gateway = true
    nat_gateway_mode        = "single"
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 1 && length(aws_eip.nat) == 1 && aws_nat_gateway.this[0].connectivity_type == "public"
    error_message = "single mode must create exactly one public NAT gateway."
  }

  assert {
    condition     = length(aws_route.application_nat) == 2 && alltrue([for r in aws_route.application_nat : r.route_table_id == "rtb-app" && r.destination_cidr_block == "0.0.0.0/0"])
    error_message = "Every application route table must get a default route to the NAT gateway, and no other table may."
  }
}

run "per_az_nat_gateways_match_the_public_subnets" {
  command = plan

  variables {
    enable_internet_gateway = true
    nat_gateway_mode        = "per_az"
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 2 && length(aws_eip.nat) == 2 && length(aws_route.application_nat) == 2
    error_message = "per_az mode must create one NAT gateway per public subnet and one route per application subnet."
  }

  # Every aws_route in the module is asserted above to sit in the public or
  # application table; nothing ever targets the database table.
  assert {
    condition     = alltrue([for r in concat(aws_route.public_internet, aws_route.application_nat) : r.route_table_id != "rtb-db"])
    error_message = "The database tier must have no route to the internet in any configuration."
  }
}

run "nat_without_an_internet_gateway_is_rejected" {
  command = plan

  variables {
    nat_gateway_mode = "single"
  }

  expect_failures = [aws_vpc.this]
}

run "unknown_nat_mode_is_rejected" {
  command = plan

  variables {
    nat_gateway_mode = "one"
  }

  expect_failures = [var.nat_gateway_mode]
}
