package verify

default allow := false

default violations := []

verify = v {
	v := {
		"allow": allow,
		"violation": {
			"type": "mismatching tool name",
			"details": violations,
		},
		"summary": [{
			"allow": allow,
			"reason": reason,
			"violations": count(violations),
		}],
	}
}

allow {
	count(violations) == 0
}

reason = v {
	allow
	v := sprintf("required tool %s is used", [input.config.args.tool_name])
}

reason = v {
	not allow
	v := sprintf("required tool %s was not found in the report", [input.config.args.tool_name])
}

violations = j {
	j := {r |
		# d := base64.decode(input.evidence.predicate.content)
		# report := json.unmarshal(d)
		actual_tool_name := input.evidence.predicate.content.runs[0].tool.driver.name
		actual_tool_name != input.config.args.tool_name
		r := {
			"tool_name": actual_tool_name,
		}
	}
}
