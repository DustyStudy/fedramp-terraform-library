locals {
  region = data.aws_region.current.name
}

data "aws_region" "current" {}

# Security Group for FIPS Interface Endpoints (TLS only, no outbound egress required)
resource "aws_security_group" "endpoints" {
  #checkov:skip=CKV_AWS_23:Interface endpoints receive TLS traffic and do not initiate egress
  name        = "${var.environment}-fips-vpce-sg"
  description = "Security group for FIPS-validated VPC interface endpoints"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow inbound TLS from VPC CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress = []

  tags = {
    Name = "${var.environment}-fips-vpce-sg"
  }
}

# Interface Endpoints with FIPS & Private DNS Enabled
resource "aws_vpc_endpoint" "fips_services" {
  for_each = toset(var.fips_endpoint_services)

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${local.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.endpoints.id]

  tags = {
    Name = "${var.environment}-${each.value}-fips-vpce"
  }
}

# Gateway Endpoint for S3
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${local.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.route_table_ids

  tags = {
    Name = "${var.environment}-s3-gateway-endpoint"
  }
}
