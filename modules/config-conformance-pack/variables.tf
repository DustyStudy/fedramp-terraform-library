variable "config_bucket_name" {
  type        = string
  default     = ""
  description = "Name for the S3 bucket storing AWS Config snapshots and history. Leave blank to auto-generate a name."

  validation {
    condition     = !can(regex("\\.", var.config_bucket_name))
    error_message = "config_bucket_name must not contain dots: S3 FIPS endpoints are virtual-hosted and do not support dotted bucket names."
  }
}

variable "conformance_pack_template" {
  type        = string
  default     = "Operational-Best-Practices-for-FedRAMP-Moderate.yaml"
  description = <<-EOT
    AWS-managed conformance pack sample template name. For High, review the
    FedRAMP High sample pack (where published) or layer additional Config
    rules on top of this baseline — the managed packs are updated
    independently of this repo, so verify current availability at
    https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html
  EOT
}
