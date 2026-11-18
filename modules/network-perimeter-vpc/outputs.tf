output "vpc_id" {
  value = aws_vpc.this.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "application_subnet_ids" {
  value = aws_subnet.application[*].id
}

output "database_subnet_ids" {
  value = aws_subnet.database[*].id
}

output "public_route_table_id" {
  description = "ID of the public tier's route table."
  value       = aws_route_table.public.id
}

output "application_route_table_ids" {
  description = "IDs of the application tier's route tables, one per application subnet, in subnet order."
  value       = aws_route_table.application[*].id
}

output "database_route_table_id" {
  description = "ID of the database tier's route table. The module never adds a route to it."
  value       = aws_route_table.database.id
}

output "dns_firewall_rule_group_id" {
  description = "ID of the DNS Firewall rule group, or null when enable_dns_firewall is false."
  value       = one(aws_route53_resolver_firewall_rule_group.this[*].id)
}
