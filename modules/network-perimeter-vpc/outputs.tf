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

output "dns_firewall_rule_group_id" {
  description = "ID of the DNS Firewall rule group, or null when enable_dns_firewall is false."
  value       = one(aws_route53_resolver_firewall_rule_group.this[*].id)
}
