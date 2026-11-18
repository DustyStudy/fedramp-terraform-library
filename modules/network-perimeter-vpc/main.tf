locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# Only read when availability_zones is not given. Local and Wavelength Zones
# are left out: they cannot host every resource type a tier may need.
data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:A zone-name allowlist would defeat the region-agnostic fallback. Subnets take the first N names in sorted order, so a zone AWS adds later never moves them; set availability_zones to pin zones.
  count = var.availability_zones == null ? 1 : 0
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  azs       = var.availability_zones != null ? var.availability_zones : data.aws_availability_zones.available[0].names
  nat_count = var.nat_gateway_mode == "none" ? 0 : var.nat_gateway_mode == "single" ? 1 : length(var.public_subnet_cidrs)
}

# KMS CMK for VPC Flow Logs
data "aws_iam_policy_document" "flow_logs_kms" {
  #checkov:skip=CKV_AWS_109:KMS administrative operations require root account wildcard
  #checkov:skip=CKV_AWS_111:KMS key management requires write access for key admins
  #checkov:skip=CKV_AWS_356:KMS key policies require wildcard resource within the key definition itself
  statement {
    sid    = "AllowRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Required: CloudWatch Logs makes its own encrypt/decrypt calls as the
  # logs service (separate from whichever IAM role publishes flow log
  # records via logs:PutLogEvents). Without this statement, the log group
  # can't be encrypted with this CMK at all.
  statement {
    sid    = "AllowCloudWatchLogsEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "flow_logs" {
  description             = "KMS Key for VPC Flow Logs CloudWatch Log Group"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.flow_logs_kms.json
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc-flow-logs/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.flow_logs.arn
}

# IAM Role for Flow Logs Publishing
data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    # Confused-deputy guard: the flow logs service can assume this role only
    # for a flow log that this account owns in this region.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:vpc-flow-log/*"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.environment}-vpc-flow-logs-role"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
      },
      {
        # DescribeLogGroups has no resource-level permissions.
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      }
    ]
  })
}

# 3-Tier Hardened VPC
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.environment}-perimeter-vpc"
  }

  # Checked here, ahead of every subnet, so a bad combination fails with these
  # messages instead of "Invalid index".
  lifecycle {
    precondition {
      condition     = max(length(var.public_subnet_cidrs), length(var.app_subnet_cidrs), length(var.db_subnet_cidrs)) <= length(local.azs)
      error_message = "Each subnet CIDR list needs its own Availability Zone: no list may be longer than availability_zones (${length(local.azs)} zone(s): ${join(", ", local.azs)})."
    }

    precondition {
      condition     = var.nat_gateway_mode == "none" || (var.enable_internet_gateway && length(var.public_subnet_cidrs) > 0)
      error_message = "nat_gateway_mode other than \"none\" needs enable_internet_gateway = true and at least one public subnet, because NAT gateways sit in the public tier."
    }
  }
}

# Default Security Group Neutralization
resource "aws_default_security_group" "default" {
  vpc_id  = aws_vpc.this.id
  ingress = []
  egress  = []
}

# Flow Logs Enforced for ALL Traffic (AU-12)
resource "aws_flow_log" "this" {
  iam_role_arn             = aws_iam_role.flow_logs.arn
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type             = "ALL"
  max_aggregation_interval = 60
  vpc_id                   = aws_vpc.this.id
}

# Subnet tiers, one subnet per CIDR, spread across the AZs in order
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-public-tier-${count.index + 1}"
  }
}

resource "aws_subnet" "application" {
  count             = length(var.app_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.app_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.environment}-app-tier-${count.index + 1}"
  }
}

resource "aws_subnet" "database" {
  count             = length(var.db_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.db_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.environment}-db-isolated-tier-${count.index + 1}"
  }
}

# One route table per tier (one per subnet for the application tier, so a
# per-AZ NAT never changes resource addresses). Each starts with the VPC-local
# route only, which is what the main route table gave these subnets before.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.environment}-public-tier"
  }
}

resource "aws_route_table" "application" {
  count  = length(var.app_subnet_cidrs)
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.environment}-app-tier-${count.index + 1}"
  }
}

# The module never adds a route to this table: the database tier has no path
# to the internet in any configuration.
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.environment}-db-isolated-tier"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "application" {
  count          = length(var.app_subnet_cidrs)
  subnet_id      = aws_subnet.application[count.index].id
  route_table_id = aws_route_table.application[count.index].id
}

resource "aws_route_table_association" "database" {
  count          = length(var.db_subnet_cidrs)
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# Opt-in internet gateway. Off by default: the library's org SCP denies
# internet gateways outside the egress account.
resource "aws_internet_gateway" "this" {
  count  = var.enable_internet_gateway ? 1 : 0
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.environment}-igw"
  }
}

resource "aws_route" "public_internet" {
  count                  = var.enable_internet_gateway ? 1 : 0
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

# Opt-in NAT for application-tier egress: one shared gateway, or one per
# public subnet (AZ).
resource "aws_eip" "nat" {
  count  = local.nat_count
  domain = "vpc"

  tags = {
    Name = "${var.environment}-nat-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "this" {
  count         = local.nat_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${var.environment}-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route" "application_nat" {
  count                  = local.nat_count > 0 ? length(var.app_subnet_cidrs) : 0
  route_table_id         = aws_route_table.application[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  # Subnet N uses the NAT in its own AZ; with fewer NATs than subnets, wrap.
  nat_gateway_id = aws_nat_gateway.this[count.index % local.nat_count].id
}

# Database-tier NACL (SC-7): in from the application tier on the database
# port, out to the application tier on ephemeral ports (NACLs are stateless),
# everything else denied by the implicit rule.
resource "aws_network_acl" "database" {
  count  = var.enable_database_nacl ? 1 : 0
  vpc_id = aws_vpc.this.id
  #checkov:skip=CKV2_AWS_1:Attached to the database subnets through subnet_ids; checkov cannot follow the reference through count
  subnet_ids = aws_subnet.database[*].id

  dynamic "ingress" {
    for_each = var.app_subnet_cidrs
    content {
      rule_no    = 100 + ingress.key
      action     = "allow"
      protocol   = "tcp"
      cidr_block = ingress.value
      from_port  = var.database_port
      to_port    = var.database_port
    }
  }

  dynamic "egress" {
    for_each = var.app_subnet_cidrs
    content {
      rule_no    = 100 + egress.key
      action     = "allow"
      protocol   = "tcp"
      cidr_block = egress.value
      from_port  = 1024
      to_port    = 65535
    }
  }

  tags = {
    Name = "${var.environment}-db-isolated-tier"
  }
}

# Opt-in DNS Firewall: block resolver lookups of known C2 relay domains (SC-7, SI-4).
# The default list is GSocket's relay network and download hosts; attackers have
# used GSocket to keep access to Linux web servers after the entry flaw was patched.
resource "aws_route53_resolver_firewall_domain_list" "blocked" {
  count   = var.enable_dns_firewall ? 1 : 0
  name    = "${var.environment}-blocked-c2-domains"
  domains = var.dns_firewall_blocked_domains
}

resource "aws_route53_resolver_firewall_rule_group" "this" {
  count = var.enable_dns_firewall ? 1 : 0
  name  = "${var.environment}-dns-firewall"
}

resource "aws_route53_resolver_firewall_rule" "block" {
  count                   = var.enable_dns_firewall ? 1 : 0
  name                    = "block-c2-domains"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.blocked[0].id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.this[0].id
  priority                = 100
}

resource "aws_route53_resolver_firewall_rule_group_association" "this" {
  count                  = var.enable_dns_firewall ? 1 : 0
  name                   = "${var.environment}-dns-firewall"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.this[0].id
  vpc_id                 = aws_vpc.this.id
  priority               = 101
  mutation_protection    = var.dns_firewall_mutation_protection ? "ENABLED" : "DISABLED"
}
