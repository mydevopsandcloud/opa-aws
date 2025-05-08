package codebuild_project_user_controlled_buildspec

default allow = false

allow {
    not user_controlled_buildspec
}

user_controlled_buildspec {
    input.buildspec != ""
    endswith(input.buildspec, ".yaml")
}

user_controlled_buildspec {
    input.buildspec != ""
    endswith(input.buildspec, ".yml")
}

violation[msg] {
    user_controlled_buildspec
    msg := sprintf("CodeBuild project %s uses a user-controlled buildspec.", [input.name])
}