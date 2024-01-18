package verify

default allow := false

default cmd := ""

default violations := []

verify = v {
	v := {
		"allow": allow,
		"violation": {
			"type": "Allowed shell access",
			"details": violations,
		},
		"summary": [{
			"allow": allow,
			"reason": reason,
		}],
	}
}

cmd = input.evidence.predicate.bom.metadata.component.properties[i].value {
	input.evidence.predicate.bom.metadata.component.properties[i].name == "entrypoint"
}

allow {
	not contains(cmd, "sh")
}

allow {
	contains(cmd, ".sh")
}

reason = v {
	allow
	v := "image entrypoint does not allow shell access"
}

reason = v {
	not allow
	v := "image entrypoint allows shell access"
}

violations = v {
	not allow
	v := [{"cmd": cmd}]
}
