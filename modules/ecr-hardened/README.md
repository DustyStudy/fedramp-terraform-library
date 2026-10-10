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
| RA-5, SC-28, SC-12 | KSI-SVC-SIN, KSI-SVC-VRI |

## Notes

- **Pushing and pulling need no KMS permissions.** ECR adds grants to the
  key when the repository is created and uses them to encrypt and decrypt
  image layers. The principal that creates or deletes the repository (the
  role running Terraform) needs `kms:CreateGrant`, `kms:RetireGrant` and
  `kms:DescribeKey` on the key. Don't revoke the grants ECR creates:
  pushes and pulls stop working at once.
- The lifecycle policy keeps the newest 30 images for each of the tag
  prefixes `v`, `prod` and `release` (one rule per prefix). Images tagged some
  other way (e.g. a bare commit SHA) aren't covered by that rule and will
  accumulate — adjust the prefixes or add a rule if your tagging
  convention differs.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| repository_name | Name of the hardened ECR repository | `string` | n/a | yes |

## Outputs

| Name | Description |
| ---- | ----------- |
| repository_arn | n/a |
| repository_url | n/a |
<!-- END_TF_DOCS -->
