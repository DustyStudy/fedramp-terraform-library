# security-hub-org

Enables AWS Security Hub with the default standards and organization
auto-enrollment. Deploy from the Security Hub delegated administrator
account.

## Usage

```hcl
module "security_hub_org" {
  source = "../../modules/security-hub-org"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| CA-7, RA-5, SI-4 | KSI-MLA-04 |

## Notes

Security Hub has since introduced a "central configuration" model (managed
via `aws_securityhub_organization_configuration`'s `organization_configuration`
block with `configuration_type = "CENTRAL"`) as an alternative to the
per-account "local" model this module uses. Central configuration lets a
delegated administrator push policy to member accounts rather than each
account auto-enabling its own standards — worth considering for larger
organizations, but it's a different operating model, not just a parameter
tweak, so it's intentionally out of scope for this module.
