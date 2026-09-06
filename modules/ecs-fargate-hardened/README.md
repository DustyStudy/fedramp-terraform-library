# ecs-fargate-hardened

An ECS cluster with Container Insights enabled and KMS-encrypted
CloudWatch Logs, including encrypted ECS Exec (`aws ecs execute-command`)
session logging.

## Usage

```hcl
module "ecs_fargate_hardened" {
  source              = "../../modules/ecs-fargate-hardened"
  cluster_name        = "my-cluster"
  log_retention_days  = 365
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AU-12, SC-13 | KSI-MLA-01 |

## Notes

- This module creates the *cluster*, not task definitions or services —
  bring your own `aws_ecs_task_definition`/`aws_ecs_service` and reference
  `cluster_arn` from this module's outputs.
- **ECS Exec needs an additional KMS grant this module doesn't provide.**
  The KMS key here covers CloudWatch Logs delivery. ECS Exec's interactive
  session data channel separately requires `kms:GenerateDataKey`/
  `kms:Decrypt` for whichever IAM principals actually run
  `execute-command` — since a reusable module can't know who those
  principals are, grant that access from your root configuration (an
  additional key-policy statement, or an IAM identity policy on those
  roles).
- `log_retention_days` defaults to 365 to match FedRAMP Moderate's
  one-year audit log retention expectation; override for High if your SSP
  calls for longer.
