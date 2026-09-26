variable "manage_default_vpc" {
  description = "Whether to manage and neutralize default VPC resources"
  type        = bool
  default     = true
}

variable "use_fips_endpoint" {
  description = <<-EOT
    Send AWS API calls to FIPS 140 validated endpoints. Class D (formerly High)
    MUST use validated cryptographic modules under FedRAMP rule CMU-CSO-UVM.
    Every service this root calls has FIPS endpoints in US commercial regions
    and GovCloud (https://aws.amazon.com/compliance/fips/); set false only for
    a region without them.
  EOT
  type        = bool
  default     = true
}
