package policy.aws.codebuild.user_controlled_buildspec

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# Metadata for the policy
metadata = {
    "id": "CB-AWS-0001",
    "title": "AWS CodeBuild project uses user-controlled buildspec",
    "description": "Ensure that AWS CodeBuild projects do not use user-controlled buildspec files (.yaml or .yml) which could lead to security risks.",
    "severity": "MEDIUM",
    "category": "Infrastructure",
    "provider": "AWS",
    "service": "CodeBuild",
    "frameworks": ["CIS", "AWS Best Practices"],
}

# Default deny is false
default deny = false

# Resource type to scan
resource_type = "aws_codebuild_project"

# Rule to check if CodeBuild project uses user-controlled buildspec
deny {
    input.resource_type == resource_type
    has_user_controlled_buildspec(input.resource_configuration.buildspec)
}

# Helper function to determine if buildspec is user-controlled
has_user_controlled_buildspec(buildspec) {
    buildspec != null
    buildspec != ""
    endswith(buildspec, ".yaml") or endswith(buildspec, ".yml")
}

# Output for passing resources
pass[resource] {
    resource := input.resources[_]
    resource.resource_type == resource_type
    not has_user_controlled_buildspec(resource.resource_configuration.buildspec)
}

# Output for failing resources
fail[resource] {
    resource := input.resources[_]
    resource.resource_type == resource_type
    has_user_controlled_buildspec(resource.resource_configuration.buildspec)
}

# Output message for passing resources
pass_message[resource_id] = message {
    resource := pass[_]
    resource_id := resource.resource_id
    message := sprintf("CodeBuild project %s does not use an user controlled buildspec.", [resource_id])
}

# Output message for failing resources
fail_message[resource_id] = message {
    resource := fail[_]
    resource_id := resource.resource_id
    message := sprintf("CodeBuild project %s uses an user controlled buildspec.", [resource_id])
}