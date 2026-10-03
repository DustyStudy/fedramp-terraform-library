# config-conformance-pack

Enables AWS Config with a continuous recorder and a KMS-encrypted delivery
channel, and optionally deploys a conformance pack such as AWS's
Operational Best Practices for FedRAMP Moderate sample.

## Usage

```hcl
module "config_conformance_pack" {
  source = "../../modules/config-conformance-pack"

  # Optional: a reviewed copy of the AWS sample pack, uploaded to your own bucket.
  # https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs
  conformance_pack_template_s3_uri = "s3://my-templates/Operational-Best-Practices-for-FedRAMP-Moderate.yaml"
}
```

Inline templates (`conformance_pack_template_body`) are limited to 51,200
bytes. The FedRAMP Moderate sample was 50,642 bytes in September 2026, so
`file(...)` works today with little headroom; S3 avoids the limit. AWS
does not host the samples in a public S3 bucket, so upload your own copy. With neither variable set, the module
enables Config recording without a conformance pack.

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| CM-2, CM-6, CM-8, CA-7, RA-5 | KSI-SVC-ACM, KSI-MLA-EVC |

## Notes

- `aws_config_configuration_recorder` only creates the recorder. It has to
  be switched on with `aws_config_configuration_recorder_status`, which
  this module includes. Forgetting that step is a common cause of "Config
  shows configured but isn't recording anything."
- AWS allows one recorder per account and region. Don't deploy this module
  where Control Tower or another tool already manages the recorder.
- When deploying to several regions, set `include_global_resource_types =
  true` in one region only, or IAM resources get recorded in each.
- AWS updates the sample conformance packs independently of this repo. Pin
  the copy you reviewed rather than pulling the latest at apply time.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| config_bucket_name | Name for the S3 bucket storing AWS Config snapshots and history. Leave blank to use aws-config-<account>-<region>. | `string` | `""` | no |
| conformance_pack_name | Name of the conformance pack, when one is deployed. | `string` | `"fedramp-moderate-pack"` | no |
| conformance_pack_template_body | YAML body of the conformance pack to deploy (at most 51,200 bytes). For larger templates use conformance_pack_template_s3_uri. Leave both null to enable Config without a conformance pack. | `string` | `null` | no |
| conformance_pack_template_s3_uri | S3 URI (s3://bucket/key) of the conformance pack template, for example a reviewed copy of Operational-Best-Practices-for-FedRAMP-Moderate.yaml from https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs. | `string` | `null` | no |
| include_global_resource_types | Record global resources such as IAM users and roles. When deploying to several regions, set true in one region only, or each region records duplicates. | `bool` | `true` | no |
| snapshot_delivery_frequency | How often Config delivers configuration snapshots to S3. | `string` | `"TwentyFour_Hours"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| config_bucket_name | S3 bucket storing AWS Config history and snapshots |
| config_recorder_name | Name of the AWS Config configuration recorder |
| config_recorder_role_arn | IAM role the Config recorder uses |
| conformance_pack_name | Name of the deployed conformance pack, or null when none is deployed |
<!-- END_TF_DOCS -->
