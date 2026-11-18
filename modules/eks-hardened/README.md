# eks-hardened

An EKS cluster with KMS envelope encryption for Kubernetes Secrets, all
five control-plane log types enabled, and a private-only API endpoint
(no public access, no public CIDRs).

## Usage

```hcl
module "eks_hardened" {
  source              = "../../modules/eks-hardened"
  cluster_name        = "my-cluster"
  kubernetes_version  = "1.36"
  private_subnet_ids  = var.private_subnet_ids

  # Admins that keep working when the role that ran `terraform apply` is
  # rotated or deleted.
  cluster_admin_principal_arns = [var.platform_admin_role_arn]
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AU-2, SC-7, SC-13 | KSI-MLA-LET, KSI-CNA-RNT, KSI-SVC-SIN |

## Notes

- This module creates the cluster and its IAM role only — node groups
  (managed, self-managed, or Fargate profiles) are separate resources you
  add on top, and will need their own IAM roles/policies.
- Because `endpoint_public_access = false`, `terraform apply` and any
  `kubectl`/Helm access must originate from inside the VPC (or over a VPN/
  Direct Connect/Transit Gateway path into it) — there is no public API
  endpoint to fall back to.
- The KMS key policy here grants the account root only. Cluster-creation
  itself typically works because the principal running `terraform apply`
  already has `kms:CreateGrant` via their own IAM permissions — if you see
  a KMS access error at cluster creation, that's the first thing to
  check; add an explicit key-policy statement for the cluster role if
  needed.
- `kubernetes_version` defaults to `"1.36"` (EKS standard support until
  August 2, 2027, per the EKS release calendar as of November 2026). Pin it
  in production: a later release of this module that moves the default
  plans an in-place control-plane upgrade for callers who rely on it, and
  EKS only upgrades one minor version at a time.
- `support_type` defaults to `"STANDARD"`. EKS's own default is `EXTENDED`,
  which silently bills extended support (several times the control-plane
  rate) once the version leaves standard support. With `STANDARD` there is
  no such charge, but **AWS automatically upgrades the control plane** when
  the version reaches end of standard support. Nodes and add-ons are not
  upgraded with it, so upgrade on your own schedule before that date. Set
  `EXTENDED` if you need the extra 12 months and accept the price.
- Cluster access uses EKS access entries (`authentication_mode = "API"`).
  The creating principal is bootstrapped as cluster admin, and every ARN in
  `cluster_admin_principal_arns` gets `AmazonEKSClusterAdminPolicy` on the
  whole cluster. Set at least one principal other than the CI role, or
  rotating that role locks everyone out of a private-only cluster.
- Authentication mode is one-way: `CONFIG_MAP` → `API_AND_CONFIG_MAP` →
  `API`, never back. `API` ignores the `aws-auth` ConfigMap, including
  node-role mappings for self-managed nodes.

## Upgrading an existing cluster to this version

Clusters created by earlier versions of this module are in `CONFIG_MAP`
mode with `EXTENDED` support. None of the changes replace the cluster;
`access_config.authentication_mode`, `upgrade_policy` and `version` are
in-place updates, and the only replace-on-change attribute
(`bootstrap_cluster_creator_admin_permissions`) is under `ignore_changes`.
Still, read the plan before applying, and:

1. Set `authentication_mode = "API_AND_CONFIG_MAP"` first. Going straight
   to the default `"API"` drops every `aws-auth` mapping and cannot be
   undone. Move to `"API"` once all mappings exist as access entries.
2. Set `kubernetes_version` to what the cluster runs today if you are not
   ready for the upgrade to `1.36` that the new default plans.
3. If the cluster already runs a version that is in extended support, set
   `support_type = "EXTENDED"` until it is upgraded.

<!-- BEGIN_TF_DOCS -->
## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| cluster_name | Name of the hardened EKS cluster | `string` | n/a | yes |
| private_subnet_ids | Private Subnet IDs for the EKS Cluster | `list(string)` | n/a | yes |
| authentication_mode | Cluster authentication mode: API (access entries only), API_AND_CONFIG_MAP, or CONFIG_MAP. One-way: a cluster can move CONFIG_MAP -> API_AND_CONFIG_MAP -> API but never back. API ignores the aws-auth ConfigMap, so move an existing cluster to API_AND_CONFIG_MAP first and migrate its mappings to access entries. | `string` | `"API"` | no |
| bootstrap_cluster_creator_admin_permissions | Give the principal that creates the cluster cluster-admin. Only read at cluster creation; changes afterwards are ignored (the provider would otherwise replace the cluster). | `bool` | `true` | no |
| cluster_admin_principal_arns | IAM role or user ARNs granted AmazonEKSClusterAdminPolicy on the whole cluster through access entries, so access does not depend on the principal that created the cluster. Requires authentication_mode API or API_AND_CONFIG_MAP. ARNs must be known at plan time. | `set(string)` | `[]` | no |
| kubernetes_version | Kubernetes control plane minor version, e.g. 1.36. EKS upgrades one minor version at a time. Keep it inside EKS standard support: with support_type STANDARD, AWS upgrades the control plane itself once the version leaves it. | `string` | `"1.36"` | no |
| log_retention_days | Retention period, in days, for the encrypted EKS control-plane log group | `number` | `365` | no |
| support_type | EKS upgrade policy. STANDARD: no extended support charges; AWS automatically upgrades the control plane when its version reaches end of standard support. EXTENDED: the cluster may stay on the version for 12 more months at the extended support price. | `string` | `"STANDARD"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| cluster_arn | n/a |
| cluster_endpoint | n/a |
<!-- END_TF_DOCS -->
