package verify

import future.keywords.in

default allow := false

default violations := []

verify = v {
	v := {
		"allow": allow,
		"violation": {
			"type": "rules",
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
	count(violations) <= input.config.args.violations_threshold
}

reason = v {
	allow
	v := sprintf("found %d violations, which is less than allowed (%d)", [count(violations), input.config.args.violations_threshold])
}

reason = v {
	not allow
	v := sprintf("found more violations (%d)than allowed (%d)", [count(violations), input.config.args.violations_threshold])
}

violations = j {
	j := {r |
		# d := base64.decode(input.evidence.predicate.content)
		# provenance := json.unmarshal(d)
		some i
		rule = input.evidence.predicate.content.runs[_].tool.driver.rules[i]
		rule.defaultConfiguration.level == "error"
		r := {
			"rule": rule.id,
			"level": rule.defaultConfiguration.level,
			"description": rule.fullDescription.text,
		}
	}
}
