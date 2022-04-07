package kubernetes.admission
                
deny[msg] {
    input.request.kind.kind == "Pod"
    not input.request.object.metadata.namespace
    msg := "Namespace should not be unspecified"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    value := input.request.object.metadata.namespace
    count(value) == 0
    msg := sprintf("Namespace should not be empty: %v", [value])          
}
        
deny[msg] {
    input.request.kind.kind == "Pod"
    value := input.request.object.metadata.namespace
    value == "default"
    msg := sprintf("Namespace should not be default: %v", [value])          
}