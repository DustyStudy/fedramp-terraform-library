# moderate/org-scp-boundary

Root configuration that applies
[`modules/org-scp-boundary`](../../modules/org-scp-boundary) as the SCP
`fedramp-moderate-authorization-boundary`.

## What it deploys

One service control policy, attached to every ID in
`target_ou_or_account_ids`. It:

- denies actions outside two approved regions, chosen by partition (see
  GovCloud below);
- denies disabling CloudTrail, Config, GuardDuty and Security Hub, and
  scheduling KMS key deletion;
- denies leaving the organization;
- denies unencrypted transport to S3, SQS and DynamoDB.

This stack leaves the module's `require_imdsv2` at its default (`false`),
so the IMDSv2 statements are not included.

## Where to run it

From the **AWS Organizations management account**, once. SCPs must be
enabled in the organization. SCPs never apply to the management account
itself.

## Inputs

| Variable | Default | Meaning |
|---|---|---|
| `target_ou_or_account_ids` | `[]` | OU or account IDs to attach the SCP to. With the default the policy is created but attached to nothing, so set it. Start with a test OU: a region lock on the wrong target stops work in every other region. |
| `exempt_principal_arns` | `[]` | Role ARNs (wildcards allowed) exempt from the security-service and account-baseline denies, for example a deployment or break-glass role. Without one, nobody in a member account, your pipeline included, can create the S3 account public access block (which `account-baseline` does), enable GuardDuty features or delete a KMS key once the SCP is attached. See the [module's variables](../../modules/org-scp-boundary/variables.tf). |
| `use_fips_endpoint` | `true` | Send API calls to FIPS endpoints. |

## GovCloud

The stack reads the partition and approves `us-gov-west-1` and
`us-gov-east-1` in GovCloud, or `us-east-1` and `us-west-2` in commercial
AWS. To approve other regions, call the module directly with your own
`approved_regions`. A GovCloud organization is separate from your
commercial one, so run this from the GovCloud organization's management
account.

## Before you apply

- No backend is configured, so state is local until you add your own
  `backend` block. No region is set either: the provider takes it from
  `AWS_REGION` or your profile.
- Run `terraform plan` first and read it. Check the caller with
  `aws sts get-caller-identity` so you know which partition and account
  the plan is for.
