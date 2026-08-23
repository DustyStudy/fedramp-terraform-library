output "incident_notification_topic_arn" {
  description = "Central SNS topic for high-severity security findings — subscribe your ticketing system, SOAR pipeline, or on-call paging integration."
  value       = aws_sns_topic.incident_notifications.arn
}
