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
