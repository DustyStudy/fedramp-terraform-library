# Strips all ingress and egress rules from an existing VPC's default
# security group (CIS 5.3-equivalent — the default security group should
# never be used, and should permit no traffic).
#
# Unlike the CloudFormation version of this library, this does NOT need a
# Lambda-backed custom resource — Terraform's aws_default_security_group
# resource lets you directly adopt and restrict the default security
# group's rules as a native resource, for any VPC (every VPC has exactly
# one default security group).
#
# Control mapping:
#   Rev5 (Moderate/High): SC-7, CM-7
#   FedRAMP 20x: KSI-CNBC-02 (network boundary controls)

resource "aws_default_security_group" "this" {
  vpc_id = var.vpc_id

  # Intentionally empty — a default security group should permit no
  # traffic. Ingress/egress rules belong on purpose-specific security
  # groups, not the one every resource gets if nothing else is specified.
  ingress = []
  egress  = []

  tags = {
    Name = "default-sg-locked-down"
  }
}
