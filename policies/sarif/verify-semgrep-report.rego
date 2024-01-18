package verify

import future.keywords.in

default allow := false

default violations := []

verify = v {
	v := {
		"allow": allow,
		"violation": {
			"type": "Violations found by semgrep",
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
	v := sprintf("found more violations (%d) than allowed (%d)", [count(violations), input.config.args.violations_threshold])
}

violations = j {
	j := {r |
		# d := base64.decode(input.evidence.predicate.content)
		# provenance := json.unmarshal(d)
		some rule_id in input.config.args.rule_ids
		run = input.evidence.predicate.content.runs[_].results[_]
		contains(run.ruleId, rule_id)
		r := {
			"rule": run.ruleId,
			"location": run.locations[0].physicalLocation.artifactLocation.uri,
		}
	}
}
