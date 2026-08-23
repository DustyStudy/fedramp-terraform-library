variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "fedramp"
}

variable "vpc_id" {
  description = "VPC ID where endpoints will be provisioned"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block allowed to communicate with endpoints"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for Interface Endpoints (must be private/isolated)"
  type        = list(string)
}

variable "route_table_ids" {
  description = "Route table IDs for S3 Gateway Endpoint"
  type        = list(string)
}

variable "fips_endpoint_services" {
  description = <<-EOT
    List of AWS services that have a dedicated FIPS-suffixed VPC endpoint
    service name (e.g. 'kms-fips' resolves to
    com.amazonaws.<region>.kms-fips). Verified against AWS's own
    PrivateLink service list — https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-privatelink-support.html
    — as of this writing, that's a short list; most services do NOT have
    a separate FIPS-suffixed endpoint (see standard_endpoint_services
    below). Re-verify against that page before adding entries, since this
    list has grown over time and will keep changing.
  EOT
  type        = list(string)
  default = [
    "kms-fips",
    "ec2-fips",
    "sts-fips",
  ]
}

variable "standard_endpoint_services" {
  description = <<-EOT
    List of AWS services needed for typical SSM/Session-Manager-based
    connectivity that do NOT have a distinct FIPS-suffixed VPC endpoint
    service name as of this writing (confirmed against AWS's PrivateLink
    service list). Where AWS does offer FIPS access to these services, it
    works through an alternate FIPS-labeled private DNS hostname on this
    SAME endpoint (e.g. monitoring-fips.<region>.amazonaws.com resolving
    through the ordinary 'monitoring' endpoint) — that's an application/
    SDK-level configuration choice (which hostname your client requests),
    not a separate piece of infrastructure this module can create. Don't
    assume these endpoints provide FIPS-validated cryptography just
    because they're deployed as part of a "FIPS" module — verify your
    application is actually requesting the FIPS hostname if that matters
    for your compliance boundary.
  EOT
  type        = list(string)
  default = [
    "secretsmanager",
    "ssm",
    "ssmmessages",
    "ec2messages",
    "ecr.api",
    "ecr.dkr",
    "logs",
    "monitoring",
  ]
}
