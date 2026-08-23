output "endpoint_security_group_id" {
  value = aws_security_group.endpoints.id
}

output "fips_endpoint_ids" {
  value = { for k, v in aws_vpc_endpoint.fips_services : k => v.id }
}
