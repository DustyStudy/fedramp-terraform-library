variable "config_bucket_name" {
  type        = string
  default     = ""
  description = "Name for the S3 bucket storing AWS Config snapshots and history. Leave blank to use aws-config-<account>-<region>."

  validation {
    condition     = !can(regex("\\.", var.config_bucket_name))
    error_message = "config_bucket_name must not contain dots: S3 FIPS endpoints are virtual-hosted and do not support dotted bucket names."
  }
}

variable "include_global_resource_types" {
  type        = bool
  default     = true
  description = "Record global resources such as IAM users and roles. When deploying to several regions, set true in one region only, or each region records duplicates."
}

variable "snapshot_delivery_frequency" {
  type        = string
  default     = "TwentyFour_Hours"
  description = "How often Config delivers configuration snapshots to S3."

  validation {
    condition     = contains(["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"], var.snapshot_delivery_frequency)
    error_message = "snapshot_delivery_frequency must be One_Hour, Three_Hours, Six_Hours, Twelve_Hours, or TwentyFour_Hours."
  }
}

variable "conformance_pack_name" {
  type        = string
  default     = "fedramp-moderate-pack"
  description = "Name of the conformance pack, when one is deployed."
}

variable "conformance_pack_template_body" {
  type        = string
  default     = null
  description = <<-EOT
    YAML body of the conformance pack to deploy (at most 51,200 bytes). For
    larger templates use conformance_pack_template_s3_uri. Leave both null
    to enable Config without a conformance pack.
  EOT
}

variable "conformance_pack_template_s3_uri" {
  type        = string
  default     = null
  description = <<-EOT
    S3 URI (s3://bucket/key) of the conformance pack template, for example
    a reviewed copy of Operational-Best-Practices-for-FedRAMP-Moderate.yaml
    from https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs.
  EOT

  validation {
    condition     = var.conformance_pack_template_s3_uri == null || can(regex("^s3://[^/]+/.+", var.conformance_pack_template_s3_uri))
    error_message = "conformance_pack_template_s3_uri must look like s3://bucket/key."
  }
}
