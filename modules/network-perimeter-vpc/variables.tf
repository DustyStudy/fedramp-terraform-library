variable "environment" {
  type    = string
  default = "fedramp"
}

variable "vpc_cidr" {
  type    = string
  default = "10.100.0.0/16"
}

variable "availability_zones" {
  description = "Availability Zones for the subnets; subnet N of each tier goes in zone N. Null uses the region's available zones in name order. No subnet CIDR list may be longer than this list."
  type        = list(string)
  default     = null
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.1.0/24", "10.100.2.0/24"]
}

variable "app_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.10.0/24", "10.100.20.0/24"]
}

variable "db_subnet_cidrs" {
  type    = list(string)
  default = ["10.100.100.0/24", "10.100.200.0/24"]
}

variable "enable_internet_gateway" {
  description = "Attach an internet gateway and give the public tier a default route to it. Off by default: the library's org SCP denies internet gateways outside the egress account."
  type        = bool
  default     = false
}

variable "nat_gateway_mode" {
  description = "NAT for application-tier egress: \"none\", \"single\" (one gateway in the first public subnet, shared by every application subnet) or \"per_az\" (one per public subnet, so losing a zone does not cut egress for the others). Anything but \"none\" needs enable_internet_gateway = true."
  type        = string
  default     = "none"

  validation {
    condition     = contains(["none", "single", "per_az"], var.nat_gateway_mode)
    error_message = "nat_gateway_mode must be \"none\", \"single\" or \"per_az\"."
  }
}

variable "enable_database_nacl" {
  description = "Put the database subnets behind a network ACL that allows only the application-tier CIDRs on database_port, plus return traffic. Set false if something outside the application tier must reach the database tier, or the database tier must open connections itself."
  type        = bool
  default     = true
}

variable "database_port" {
  description = "TCP port the database-tier network ACL allows from the application tier (5432 PostgreSQL, 3306 MySQL, 1433 SQL Server)."
  type        = number
  default     = 5432

  validation {
    condition     = var.database_port >= 1 && var.database_port <= 65535
    error_message = "database_port must be between 1 and 65535."
  }
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "enable_dns_firewall" {
  description = "Attach a Route 53 Resolver DNS Firewall rule group to the VPC that blocks dns_firewall_blocked_domains."
  type        = bool
  default     = false
}

variable "dns_firewall_blocked_domains" {
  description = "Domains the DNS Firewall answers with NXDOMAIN. A leading *. matches subdomains only, so list the apex too. The default is GSocket's relay network ([a-z].gs.thc.org) and its download hosts (gsocket.io)."
  type        = list(string)
  default     = ["gs.thc.org", "*.gs.thc.org", "gsocket.io", "*.gsocket.io"]

  validation {
    condition     = length(var.dns_firewall_blocked_domains) > 0
    error_message = "dns_firewall_blocked_domains must list at least one domain."
  }
}

variable "dns_firewall_mutation_protection" {
  description = "Stop the DNS Firewall association from being changed or removed. AWS refuses to remove a protected association, so to turn the firewall off or destroy the module, apply with this set to false first."
  type        = bool
  default     = true
}
