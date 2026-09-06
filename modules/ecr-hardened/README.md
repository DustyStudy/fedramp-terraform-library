# ecr-hardened

A KMS-encrypted ECR repository with immutable tags, scan-on-push, and a
lifecycle policy that expires untagged images after 14 days while
retaining the most recent 30 tagged production images.

## Usage

```hcl
module "ecr_hardened" {
  source          = "../../modules/ecr-hardened"
  repository_name = "my-service"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| RA-5, SC-28, SC-12 | KSI-SVC-02 |

## Notes

- **You must grant KMS access to whoever pushes/pulls images.** Unlike
  CloudWatch Logs, ECR authorizes image push/pull through the calling IAM
  principal (a developer, CI/CD role, or ECS/EKS task execution role)
  rather than through a fixed service-principal grant on the key. This
  module's key policy only grants the account root — add
  `kms:GenerateDataKey`/`kms:Decrypt` for the actual pushing/pulling
  principals via an IAM identity policy on their role, or an additional
  key-policy statement in your root configuration.
- The lifecycle policy's "retain 30 tagged images" rule only matches tags
  prefixed `v`, `prod`, or `release` (`tagPrefixList`). Images tagged some
  other way (e.g. a bare commit SHA) aren't covered by that rule and will
  accumulate — adjust the prefix list or add a rule if your tagging
  convention differs.
