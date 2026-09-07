# Examples

Every module's own README shows it in isolation. These two root
configurations show how a realistic set of them compose into an actual
account baseline — which is the part isolated module docs can't
demonstrate.

## Why two roots, not one

FedRAMP baselines (and AWS multi-account design generally) split
responsibility between the **Organizations management account** and
**member accounts**. A single Terraform root with one `aws` provider
can't correctly represent both — org-wide resources like an organization
CloudTrail trail, GuardDuty's organization configuration, and SCPs can
only be created from the management account, while things like a VPC or
an RDS instance belong in a workload/member account.

| Root | Run from | What it deploys |
|---|---|---|
| [`management-account-baseline/`](./management-account-baseline) | AWS Organizations management account | Org CloudTrail, GuardDuty org auto-enrollment, Security Hub org auto-enrollment, region-lock + governance SCPs, CIS CloudWatch alarms |
| [`member-account-baseline/`](./member-account-baseline) | Each workload/member account | Account baseline hardening, a 3-tier VPC, AWS Config conformance pack, IAM access controls, incident notification routing |

Run `management-account-baseline/` once, against the management account.
Run `member-account-baseline/` once per workload account (a new copy of
the state per account — this is not a module you count on GuardDuty/
Security Hub org auto-enrollment to skip).

## Two duplicate-resource conflicts found while building these examples

Composing modules together surfaced two real bugs that aren't visible
when you only ever look at one module at a time — both are call-outs in
`member-account-baseline/main.tf`, and both should be fixed at the
module level too:

1. **`account-baseline` and `iam-password-policy` both create
   `aws_iam_account_password_policy`.** AWS accounts have exactly one
   password policy, so using both modules in the same account means one
   `terraform apply` silently undoes the other's settings on every run.
   `member-account-baseline` uses `account-baseline` only, and
   `iam-password-policy`'s own README should note it's redundant with
   `account-baseline`'s `manage_password_policy`-style variables.
2. **`account-baseline` (`manage_default_vpc = true`) and
   `moderate/network-boundary/default-security-group-lockdown` both
   manage `aws_default_security_group`** when pointed at the same
   account's default VPC. `member-account-baseline` uses
   `account-baseline` for that and skips the standalone lockdown module;
   the standalone module is really for a default VPC in an account where
   `account-baseline` isn't deployed (or was deployed with
   `manage_default_vpc = false`).

## Running an example

```bash
cd examples/management-account-baseline
terraform init
terraform plan -var="organization_id=o-xxxxxxxxxx"
```

These roots are meant to be copied into your own repo and adapted — not
applied as-is against a production Organization. Review every variable
default first.
