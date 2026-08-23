variable "config_bucket_name" {
  type        = string
  default     = ""
  description = "Name for the S3 bucket storing AWS Config snapshots and history. Leave blank to auto-generate a name."
}

variable "conformance_pack_template" {
  type    = string
  default = "Operational-Best-Practices-for-FedRAMP-Moderate.yaml"
  description = <<-EOT
    AWS-managed conformance pack sample template name. For High, review the
    FedRAMP High sample pack (where published) or layer additional Config
    rules on top of this baseline — the managed packs are updated
    independently of this repo, so verify current availability at
    https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html
  EOT
}
