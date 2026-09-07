output "vpc_id" {
  value = module.network_perimeter_vpc.vpc_id
}

output "permission_boundary_arn" {
  description = "Attach as permissions_boundary when creating human/developer IAM roles or users in this account"
  value       = module.iam_access_control.permission_boundary_arn
}

output "incident_notification_topic_arn" {
  description = "Subscribe your ticketing system, SOAR pipeline, or on-call paging integration"
  value       = module.incident_notifications.incident_notification_topic_arn
}
