# config-conformance-pack

Enables AWS Config with a continuous recorder and delivery channel, plus the
AWS-managed Operational Best Practices for FedRAMP Moderate conformance
pack.

## Usage

```hcl
module "config_conformance_pack" {
  source = "../../modules/config-conformance-pack"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| CM-2, CM-6, CM-8, CA-7, RA-5 | KSI-CNBC-01, KSI-CNBC-02 |

## Notes

- `aws_config_configuration_recorder` only creates the recorder — it has to
  be separately switched on via `aws_config_configuration_recorder_status`,
  which this module includes. It's an easy step to forget and a common
  cause of "Config shows configured but isn't recording anything."
- The conformance pack template is pulled from AWS's own managed S3 bucket
  of sample templates. That bucket's contents are updated independently of
  this repo — verify the template name/path is still current before relying
  on it: https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html
