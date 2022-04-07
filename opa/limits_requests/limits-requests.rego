package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec["containers"][_]
    not count(container.resources) > 0 # resources is automatically created empty if it does not exist
    msg := "resources not specified in spec.containers"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec["containers"][_]
    not container.resources.limits
    msg := "limits not specified in spec.containers.resources"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec["containers"][_]
    not container.resources.requests
    msg := "requests not specified in spec.containers.resources"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec["containers"][_]
    not container.resources.requests.cpu
    msg := "cpu not specified in spec.containers.resources.requests"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec["containers"][_]
    not container.resources.requests.memory
    msg := "memory not specified in spec.containers.resources.requests"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec["containers"][_]
    not container.resources.limits.cpu
    msg := "cpu not specified in spec.containers.resources.limits"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec["containers"][_]
    not container.resources.limits.memory
    msg := "memory not specified in spec.containers.resources.limits"
}


