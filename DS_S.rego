package main

deny[result] {
    project := input.aws.codebuild.projects[_]
    buildspec := project.buildspec
    is_user_controlled_buildspec(buildspec)
    result := {
        "resource": project,
        "message": sprintf("CodeBuild project %s uses an user controlled buildspec.", [project.name])
    }
}

is_user_controlled_buildspec(buildspec) {
    endswith(buildspec, ".yaml")
}

is_user_controlled_buildspec(buildspec) {
    endswith(buildspec, ".yml")
}