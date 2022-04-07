package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext["readOnlyRootFilesystem"]
    msg := "spec.securityContext.containers.readOnlyRootFilesystem not specified, should be set to true"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.containers[_].securityContext["readOnlyRootFilesystem"] == false
    msg := "spec.securityContext.containers.readOnlyRootFilesystem false, should be set to true"
}