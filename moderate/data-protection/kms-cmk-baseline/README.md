# kms-cmk-baseline

Reusable customer-managed KMS key (CMK) with rotation enabled, for
encrypting data at rest in services that don't warrant a dedicated key.

## Usage

```hcl
module "app_data_key" {
  source              = "../../moderate/data-protection/kms-cmk-baseline"
  key_alias           = "app-data"
  admin_role_arn      = "arn:aws:iam::123456789012:role/SecurityAdmin"
  key_user_role_arns  = ["arn:aws:iam::123456789012:role/AppExecutionRole"]
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| SC-12, SC-13, SC-28 | KSI-SVC-02 |

## Notes

Deploy one instance of this module per workload or data-classification
tier rather than sharing a single key across unrelated systems — that
keeps blast radius contained if one workload's access needs to be revoked
or investigated independently of others.
