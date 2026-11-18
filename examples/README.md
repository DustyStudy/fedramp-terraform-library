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
| [`management-account-baseline/`](./management-account-baseline) | AWS Organizations management account (it assumes a role into the security account for GuardDuty and Security Hub) | Org CloudTrail, GuardDuty and Security Hub delegated-administrator designation plus org auto-enrollment, region-lock + governance SCPs, CIS CloudWatch alarms |
| [`member-account-baseline/`](./member-account-baseline) | Each workload/member account | Account baseline hardening, a 3-tier VPC, AWS Config conformance pack, IAM access controls, incident notification routing |

Run `management-account-baseline/` once, against the management account.
Run `member-account-baseline/` once per workload account (a new copy of
the state per account — this is not a module you count on GuardDuty/
Security Hub org auto-enrollment to skip).

## Apply order and what each step needs

1. **`management-account-baseline/` first**, with management account
   credentials. Required inputs besides `organization_id` and
   `target_ou_or_account_ids`:
   - `security_account_id`: the account that becomes the GuardDuty and
     Security Hub delegated administrator. The root designates it from
     the management account, then configures both services inside it
     through the `aws.security` provider alias
     (`security-account.tf`), which assumes
     `security_account_role_name` (default
     `OrganizationAccountAccessRole`) there. `guardduty-org` and
     `security-hub-org` only work in the delegated administrator
     account; run from the management account, their organization
     configuration calls fail. This was the smaller fix compared with a
     third example root for the security account.
   - `exempt_principal_arns`: roles the boundary SCP's security-service
     and account-baseline denies skip. It has no default because step 2
     fails without it: the SCP denies `s3:PutAccountPublicAccessBlock`,
     `guardduty:UpdateDetector`, `kms:ScheduleKeyDeletion` and the
     Config delete calls for everyone else. List the role that applies
     `member-account-baseline/` in each member account, and, if the
     security account sits under a targeted OU, the role this root
     assumes there. `org-scp-boundary` warns at plan time when the list
     is empty while targets are attached.
   - `approved_regions` is optional: left unset, the region lock allows
     `us-gov-west-1`/`us-gov-east-1` in GovCloud and
     `us-east-1`/`us-west-2` elsewhere. Regions from the other partition
     are rejected at plan time.
2. **`member-account-baseline/` second**, once per workload account,
   using a role matched by `exempt_principal_arns`.

Prerequisites this root does not create: the organization with SCPs
enabled, and the security account with the assumable role. The two
designations turn on Organizations trusted access for GuardDuty and
Security Hub themselves, so the management account role needs
`organizations:EnableAWSServiceAccess` and
`organizations:RegisterDelegatedAdministrator`. Designations are per
region; this root covers the provider's region only.

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
terraform plan \
  -var='organization_id=o-xxxxxxxxxx' \
  -var='target_ou_or_account_ids=["ou-xxxx-xxxxxxxx"]' \
  -var='security_account_id=111122223333' \
  -var='exempt_principal_arns=["arn:<partition>:iam::*:role/terraform-deployer"]'
```

These roots are meant to be copied into your own repo and adapted — not
applied as-is against a production Organization. Review every variable
default first.
