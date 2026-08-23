output "endpoint_security_group_id" {
  value = aws_security_group.endpoints.id
}

output "fips_endpoint_ids" {
  description = "Endpoint IDs for services with a dedicated FIPS-suffixed VPC endpoint service name"
  value       = { for k, v in aws_vpc_endpoint.fips_services : k => v.id }
}

output "standard_endpoint_ids" {
  description = "Endpoint IDs for services without a distinct FIPS-suffixed service name (see variables.tf note)"
  value       = { for k, v in aws_vpc_endpoint.standard_services : k => v.id }
}
