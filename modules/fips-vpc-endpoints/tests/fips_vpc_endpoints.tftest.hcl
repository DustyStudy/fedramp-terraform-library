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
  target = data.aws_region.current
  values = {
    name = "us-gov-west-1"
  }
}

variables {
  vpc_id          = "vpc-0aaaaaaaaaaaaaaa1"
  vpc_cidr        = "10.0.0.0/16"
  subnet_ids      = ["subnet-0aaaaaaaaaaaaaaa1", "subnet-0aaaaaaaaaaaaaaa2"]
  route_table_ids = ["rtb-0aaaaaaaaaaaaaaa1"]
}

run "fips_service_names" {
  command = plan

  assert {
    condition = toset([for e in aws_vpc_endpoint.fips_services : e.service_name]) == toset([
      "com.amazonaws.us-gov-west-1.kms-fips",
      "com.amazonaws.us-gov-west-1.ec2-fips",
      "com.amazonaws.us-gov-west-1.sts-fips",
    ])
    error_message = "KMS, EC2 and STS must use their -fips endpoint services in the current region (SC-13)."
  }

  assert {
    condition     = alltrue([for e in merge(aws_vpc_endpoint.fips_services, aws_vpc_endpoint.standard_services) : e.vpc_endpoint_type == "Interface" && e.private_dns_enabled])
    error_message = "Interface endpoints must turn on private DNS so SDK calls stay inside the VPC (SC-7)."
  }

  assert {
    condition = toset([for e in aws_vpc_endpoint.standard_services : e.service_name]) == toset([
      for svc in ["secretsmanager", "ssm", "ssmmessages", "ec2messages", "ecr.api", "ecr.dkr", "logs", "monitoring"] : "com.amazonaws.us-gov-west-1.${svc}"
    ])
    error_message = "The default SSM, ECR, logging and Secrets Manager endpoints must all be created."
  }

  assert {
    condition     = alltrue([for e in merge(aws_vpc_endpoint.fips_services, aws_vpc_endpoint.standard_services) : toset(e.subnet_ids) == toset(["subnet-0aaaaaaaaaaaaaaa1", "subnet-0aaaaaaaaaaaaaaa2"])])
    error_message = "Interface endpoints must be placed in the given subnets."
  }

  assert {
    condition     = toset(aws_vpc_endpoint.s3.route_table_ids) == toset(["rtb-0aaaaaaaaaaaaaaa1"])
    error_message = "The S3 gateway endpoint must be added to the given route tables."
  }

  assert {
    condition     = aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway" && aws_vpc_endpoint.s3.service_name == "com.amazonaws.us-gov-west-1.s3"
    error_message = "S3 must use a gateway endpoint in the current region."
  }
}

run "security_group_is_tls_from_vpc_only" {
  command = plan

  assert {
    condition = alltrue([
      for r in aws_security_group.endpoints.ingress :
      r.from_port == 443 && r.to_port == 443 && r.protocol == "tcp" && toset(r.cidr_blocks) == toset(["10.0.0.0/16"])
      && length(r.ipv6_cidr_blocks) == 0 && length(r.security_groups) == 0 && length(r.prefix_list_ids) == 0 && !r.self
    ]) && length(aws_security_group.endpoints.ingress) == 1
    error_message = "The endpoint security group may only allow TLS from the VPC CIDR (SC-7)."
  }

  assert {
    condition     = length(aws_security_group.endpoints.egress) == 0
    error_message = "The endpoint security group must not allow egress."
  }
}

run "extra_fips_services" {
  command = plan

  variables {
    fips_endpoint_services     = ["kms-fips", "s3-fips"]
    standard_endpoint_services = []
  }

  assert {
    condition     = length(aws_vpc_endpoint.fips_services) == 2 && length(aws_vpc_endpoint.standard_services) == 0
    error_message = "The endpoint lists must drive the endpoints created."
  }
}
