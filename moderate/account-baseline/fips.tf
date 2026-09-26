variable "use_fips_endpoint" {
  description = <<-EOT
    Send all AWS API calls to FIPS 140 validated endpoints (default true).
    FedRAMP CMU-CSO-UVM: validated crypto is a MUST for Class D and a SHOULD
    for Class C. Every service this library calls has FIPS endpoints in the
    US commercial regions and GovCloud (https://aws.amazon.com/compliance/fips/).
    Set false only for a region without them.
  EOT
  type        = bool
  default     = true
}
