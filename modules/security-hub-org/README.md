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
| CA-7, RA-5, SI-4 | KSI-MLA-EVC, KSI-CNA-EIS |

## Notes

The organization configuration only works in the delegated administrator
account, after the management account has created
`aws_securityhub_organization_admin_account`. Designating an account also
enables Security Hub in it, which makes this module's
`aws_securityhub_account` fail as already enabled, so enable first and
designate second: have the designation `depends_on` this module's
`security_hub_account_id` output and pass its `id` back in as
`delegated_admin_account_id`. `examples/management-account-baseline` does
exactly that. If the account was designated before this module ran,
import the hub instead:
`terraform import module.security_hub_org.aws_securityhub_account.this <account-id>`.

Security Hub has since introduced a "central configuration" model (managed
via `aws_securityhub_organization_configuration`'s `organization_configuration`
block with `configuration_type = "CENTRAL"`) as an alternative to the
per-account "local" model this module uses. Central configuration lets a
delegated administrator push policy to member accounts rather than each
account auto-enabling its own standards — worth considering for larger
organizations, but it's a different operating model, not just a parameter
tweak, so it's intentionally out of scope for this module.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| auto_enable_standards | Automatically enable default security standards for new accounts joining the organization. | `bool` | `true` | no |
| delegated_admin_account_id | Account ID of the Security Hub delegated administrator. Pass aws_securityhub_organization_admin_account.<name>.id when the same root designates it: the organization configuration then waits for the designation, and the plan fails if this module's provider is not that account. Security Hub itself is still enabled first, which the designation needs to not collide with (designating an account enables Security Hub in it). null skips both. | `string` | `null` | no |
| enable_finding_aggregator | Make this region the Security Hub aggregation region, collecting findings from all regions. Set true in exactly one region of the delegated admin account. | `bool` | `false` | no |
| enable_nist_800_53 | Subscribe this account to the NIST SP 800-53 Rev5 standard, the control catalog FedRAMP is built on. | `bool` | `true` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| security_hub_account_id | ID of the Security Hub account resource (indicates Security Hub is enabled) |
<!-- END_TF_DOCS -->
