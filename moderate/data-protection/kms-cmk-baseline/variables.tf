variable "key_alias" {
  type        = string
  description = "Alias for the key (without the 'alias/' prefix), e.g. 'app-data' or 'workload-x'."
}

variable "admin_role_arn" {
  type        = string
  default     = ""
  description = <<-EOT
    ARN of an IAM role/user that should be able to administer this key
    (rotate, disable, schedule deletion) beyond the account root. Leave
    blank to grant only the account root.
  EOT
}

variable "key_user_role_arns" {
  type        = list(string)
  default     = []
  description = <<-EOT
    ARNs of IAM roles that should be able to use this key to
    encrypt/decrypt data (e.g. an application's execution role).
  EOT
}
