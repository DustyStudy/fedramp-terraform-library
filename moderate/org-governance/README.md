# moderate/org-governance

Root configuration that applies
[`modules/org-governance`](../../modules/org-governance) with the
Moderate-track backup retention.

## What it deploys

Three AWS Organizations policies, each attached to every ID in
`target_ou_or_account_ids`:

- A workload-perimeter SCP: denies root usage, direct internet gateways,
  and local IAM users and access keys, and protects S3 Object Lock
  settings.
- An AI-services opt-out policy.
- A backup policy with 365 days of retention, running in two regions
  chosen by partition (see GovCloud below).

Read the notes in the
[module README](../../modules/org-governance/README.md) before attaching
it. In particular:

- The SCP breaks any workload that still uses IAM users or long-lived
  access keys.
- This stack does not expose the module's
  `authorized_security_admin_arns`, so no principal is exempt from the
  Object Lock protection.
- The backup policy writes to the vault `FedRAMPComplianceVault`, which
  must already exist in every target account and backup region. Apply
  [`moderate/account-baseline`](../account-baseline) there first.
- 365 days is this track's starting value, not a FedRAMP figure. Set
  retention from your own contingency plan.

## Where to run it

From the **AWS Organizations management account**, once. The service
control, AI-services opt-out and backup policy types must already be
enabled in the organization.

## Inputs

| Variable | Default | Meaning |
|---|---|---|
| `target_ou_or_account_ids` | `[]` | OU or account IDs to attach the three policies to. With the default the policies are created but attached to nothing, so set it. Start with a test OU. |
| `use_fips_endpoint` | `true` | Send API calls to FIPS endpoints. |

## GovCloud

The stack reads the partition and sets `backup_regions` to
`us-gov-west-1` and `us-gov-east-1` in GovCloud, or `us-east-1` and
`us-west-2` in commercial AWS. A GovCloud organization is separate from
your commercial one, so run this from the GovCloud organization's
management account.

## Before you apply

- No backend is configured, so state is local until you add your own
  `backend` block. No region is set either: the provider takes it from
  `AWS_REGION` or your profile.
- Run `terraform plan` first and read it. Check the caller with
  `aws sts get-caller-identity` so you know which partition and account
  the plan is for.
