output "cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.ecs.arn
}
