# default-security-group-lockdown

Strips all ingress and egress rules from an existing VPC's default
security group (CIS 5.3-equivalent).

## Usage

```hcl
module "default_sg_lockdown" {
  source = "../../moderate/network-boundary/default-security-group-lockdown"
  vpc_id = "vpc-xxxxxxxxxxxxxxxxx"
}
```

## Control mapping

| Rev5 | 20x KSI |
|---|---|
| SC-7, CM-7 | KSI-CNBC-02 |

## Notes

- **Native resource, unlike CloudFormation.** `aws_default_security_group`
  lets Terraform directly adopt and restrict an existing VPC's default
  security group — the CloudFormation version of this library needed a
  Lambda-backed custom resource for the same thing, since CFN can't
  otherwise manage the default SG's rules.
- If you created your VPC through `modules/network-perimeter-vpc`, that
  module already locks down its own default security group — you don't
  need this module too. Use this one for a VPC that already exists
  outside that module.
