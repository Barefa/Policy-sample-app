package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.securityContext.runAsUser == 0
    msg := "Pod must have spec.securityContext.runAsUser unset or set to a number greater than zero"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.containers[_].securityContext.runAsUser == 0
    msg := "Pod must have spec.containers[*].securityContext.runAsUser unset or set to a number greater than zero"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.initContainers[_].securityContext.runAsUser == 0
    msg := "Pod must have spec.initContainers[*].securityContext.runAsUser unset or set to a number greater than zero"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.ephemeralContainers[_].securityContext.runAsUser == 0
    msg := "Pod must have spec.ephemeralContainers[*].securityContext.runAsUser unset or set to a number greater than zero"
}