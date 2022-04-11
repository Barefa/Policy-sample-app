package kubernetes.admission
import data.kubernetes.networkpolicies

# Deny with a message
deny[msg]{
	input.request.kind.kind == "Pod"
	pod_label_value := {v["app"] | v := input.request.object.metadata.labels} # true
    contains_label(pod_label_value,"prop")
    np_label_value := {v["app"] | v := networkpolicies[_].spec.podSelector.matchLabels}
    not contains_label(np_label_value,"prop")
	msg:= sprintf("The Pod: %v could not be created because it is missing an associated Network Security Policy. %v %v",[input.request.object.metadata.name, pod_label_value, np_label_value])
}

contains_label(arr,val){
	arr[_] == val
}