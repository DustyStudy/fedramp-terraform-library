# eks-hardened

An EKS cluster with KMS envelope encryption for Kubernetes Secrets, all
five control-plane log types enabled, and a private-only API endpoint
(no public access, no public CIDRs).

## Usage

```hcl
module "eks_hardened" {
  source              = "../../modules/eks-hardened"
  cluster_name        = "my-cluster"
  kubernetes_version  = "1.30"
  private_subnet_ids  = var.private_subnet_ids
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| AU-2, SC-7, SC-13 | KSI-MLA-01, KSI-CNBC-02 |

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
- `kubernetes_version` defaults to `"1.30"` — EKS deprecates old versions
  on its own schedule, so confirm this is still a supported version before
  relying on the default.
