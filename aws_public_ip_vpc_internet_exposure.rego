package wiz.policy

default allow = true

deny[reason] {
  some i
  resource := input.aws_network_interfaces[i]

  # Condition 1: Resource has a public IP
  resource.public_ip_assigned == true

  # Condition 2: Connected subnet is public (routes 0.0.0.0/0 to IGW)
  resource.subnet.public == true

  # Condition 3: Security group allows ingress from 0.0.0.0/0
  some j
  sg := resource.security_groups[j]
  some k
  rule := sg.ingress_rules[k]
  rule.cidr == "0.0.0.0/0"

  reason := sprintf("Resource %s in public subnet has a public IP and is reachable from the internet via security group %s", [resource.resource_id, sg.group_id])
}
