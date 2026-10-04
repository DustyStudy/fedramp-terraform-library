# trust-policy-auditor

Audits who can reach into your AWS accounts from outside them, on a
schedule: IAM role trust policies (OIDC and cross-account), Lambda
function policies, and RAM resource shares. **Detective only**. It never
edits a policy or share, because cutting off a deploy pipeline or a vendor
integration by surprise is its own incident. A human reviews and fixes.

## The risk this targets

Most cloud intrusions now start with identity, not the network. Three
patterns come up again and again:

- A role that trusts GitHub Actions through OIDC with no `sub` condition,
  or a wildcard in it. Any workflow in any repository (or in any
  repository of your organization) can then get your credentials.
- A role or function that trusts `"*"` or an account nobody recognizes,
  left over from a proof of concept or a vendor trial.
- A resource share or Lambda permission that quietly reaches outside the
  organization.

SCPs can stop some of this from being created (see
[aws-org-guardrails](https://github.com/DustyStudy/aws-org-guardrails) for
a resource-sharing SCP), but they can't read what a trust policy says.
This module does.

## What it reports

| Check | Finding | Severity |
|---|---|---|
| OIDC trust | GitHub trust with no `sub` condition | CRITICAL |
| | `sub` wildcard in the owner (`repo:*`, `repo:acme*/...`) | CRITICAL |
| | `sub` wildcard in the repository (`repo:acme/*`) | HIGH |
| | Other OIDC provider (EKS, Cognito, ...) with no `sub` condition | HIGH |
| | No `aud` condition | HIGH |
| | `sub` wildcard in the branch or environment (`repo:acme/app:*`) | MEDIUM |
| | Owner and repository IDs not pinned in the `repo:OWNER@ID/REPO@ID` format | LOW |
| Cross-account trust | `Principal: "*"` with no `aws:PrincipalOrgID`, account or ARN condition | CRITICAL |
| | An account outside the organization, with no `sts:ExternalId` condition | HIGH |
| Lambda function policy | `Principal: "*"` with no source or organization condition | CRITICAL |
| | Public function URL (`AuthType NONE`) | HIGH |
| | An account outside the organization can invoke it | HIGH |
| | A service principal with no `aws:SourceArn` or `aws:SourceAccount` (confused deputy) | MEDIUM |
| RAM share | Shared with an account outside the organization | HIGH |
| | Allows principals outside the organization | MEDIUM |

`sub` patterns are only treated as wildcards under a `*Like` operator.
Under `StringEquals`, a `*` is a literal character and matches nothing
else. Condition keys are compared case-insensitively, as IAM does.

Findings go to one SNS summary, grouped by severity. A clean run sends
nothing. An account the Lambda couldn't reach is listed under "Accounts
not scanned" rather than left out, so a failure never looks clean.

## Using Terraform

Single account:

```hcl
module "trust_policy_auditor" {
  source = "../../modules/trust-policy-auditor"

  notification_email = "you@example.com"
  regions            = ["us-east-1", "us-west-2"]
}
```

Whole organization: deploy in the management account or a delegated
administrator (the Lambda needs `organizations:ListAccounts`), and give
each member account a read-only role for it to assume.

```hcl
module "trust_policy_auditor" {
  source = "../../modules/trust-policy-auditor"

  notification_email  = "you@example.com"
  regions             = ["us-east-1", "us-west-2"]
  member_role_name    = "trust-policy-audit-read"
  trusted_account_ids = ["111122223333"] # a vendor you've reviewed
}

# In each member account (for example with a provider alias per account):
resource "aws_iam_role" "trust_policy_audit_read" {
  name = "trust-policy-audit-read"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = module.trust_policy_auditor.lambda_role_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "trust_policy_audit_read" {
  role   = aws_iam_role.trust_policy_audit_read.id
  policy = module.trust_policy_auditor.member_role_policy_json
}
```

An existing read-only audit role works too, if it allows
`iam:ListRoles`, `lambda:ListFunctions`, `lambda:GetPolicy`,
`ram:GetResourceShares` and `ram:GetResourceShareAssociations` and trusts
the Lambda role.

Works the same in GovCloud. `use_fips_endpoint` defaults to `true`; every
API it calls resolves to a FIPS endpoint in us-east-1, us-east-2 and
us-west-2. Check the regions you list in `regions` if you add others.

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AC-3, AC-6, AC-21, IA-5, SC-7 | KSI-IAM-SNU, KSI-IAM-ELP |

Supports the review of non-user authentication (OIDC federation for
pipelines) and of access granted across the authorization boundary.
Detective only: a human still decides what to change.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| code_signing_config_arn | Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip. | `string` | `null` | no |
| member_role_name | Name of a read-only role to assume in every other active account of the organization. Empty scans only the account the module is deployed in. The role must trust this module's Lambda role (output lambda_role_arn) and allow the actions in output member_role_policy_json. | `string` | `""` | no |
| name_prefix | Prefix used for naming all resources created by this module. | `string` | `"trust-policy-auditor"` | no |
| notification_email | Optional email address to subscribe to the SNS topic. Leave empty to skip. | `string` | `""` | no |
| regions | Regions to audit Lambda function policies and RAM shares in. Empty means the region the module is deployed in. IAM roles are global and always audited. | `list(string)` | `[]` | no |
| schedule_expression | EventBridge schedule expression controlling how often the audit runs. | `string` | `"rate(1 day)"` | no |
| trusted_account_ids | Accounts outside the organization to treat as trusted, such as a vendor you've reviewed. Trust in them isn't reported. | `list(string)` | `[]` | no |
| reserved_concurrent_executions | Concurrency reserved for the Lambda. Set -1 to reserve none: accounts at the 10-execution quota floor (new and sandbox accounts) reject any reservation. | `number` | `2` | no |
| use_fips_endpoint | Make the Lambda's AWS SDK calls through FIPS 140 validated endpoints (sets AWS_USE_FIPS_ENDPOINT). Default true, matching the provider setting in this library's root configurations. | `bool` | `true` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| lambda_function_arn | ARN of the auditor Lambda function. |
| lambda_role_arn | ARN of the auditor's execution role. Member-account roles named by member_role_name must trust it. |
| member_role_policy_json | Read-only permissions the member-account role needs. Attach it to the role named by member_role_name in each account. |
| sns_topic_arn | ARN of the SNS topic used for audit notifications. |
<!-- END_TF_DOCS -->

## Notes

- Without `organizations:ListAccounts` (for example, deployed in a member
  account), "outside the organization" can't be known. Those checks are
  skipped and the report says so; the OIDC and `"*"` checks still run.
- Service-linked roles and SAML federation are skipped: AWS manages the
  first, and SAML trust is governed by your identity provider.
- False positives are expected. A vendor role with an `sts:ExternalId` is
  fine and isn't reported; a vendor role without one is, even if you
  trust the vendor. Add reviewed vendors to `trusted_account_ids`.
- This complements [`org-scp-boundary`](../org-scp-boundary/) and
  [`identity-center-access-auditor`](../identity-center-access-auditor/),
  which cover what principals may do and how people get access. This
  module covers who outside the account can become a principal.
