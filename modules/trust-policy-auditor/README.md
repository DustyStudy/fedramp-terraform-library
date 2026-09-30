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

## Variables

| Variable | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `trust-policy-auditor` |
| `notification_email` | Email to subscribe to the SNS topic | `""` (no subscription) |
| `schedule_expression` | EventBridge schedule | `rate(1 day)` |
| `regions` | Regions to audit Lambda and RAM in (IAM is global) | `[]` (the deployed region) |
| `member_role_name` | Role to assume in every other active account | `""` (this account only) |
| `trusted_account_ids` | Accounts outside the organization to treat as trusted | `[]` |
| `code_signing_config_arn` | ARN of an existing `aws_lambda_code_signing_config` to enforce | `null` |
| `use_fips_endpoint` | Make the Lambda's SDK calls through FIPS endpoints (`AWS_USE_FIPS_ENDPOINT`) | `true` |

## Outputs

| Output | Description |
|---|---|
| `lambda_function_arn` | ARN of the auditor Lambda |
| `lambda_role_arn` | ARN of its execution role, for member-role trust policies |
| `sns_topic_arn` | ARN of the notification topic |
| `member_role_policy_json` | Read-only policy for the member-account role |

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
