package verify

default allow = false

default exceeding = 0

default violations = []

verify = v {
	v := {
		"allow": allow,
		"summary": [{
			"allow": allow,
			"violation": {
				"type": "Too Old SBOM",
				"details": violations,
			},
			"reason": reason,
			"violations": exceeding,
		}],
	}
}

nanosecs_per_second = (1000 * 1000) * 1000

nanosecs_per_day = ((24 * 60) * 60) * nanosecs_per_second

maximum_age = input.config.args.max_days * nanosecs_per_day

timestamp = time.parse_rfc3339_ns(input.evidence.predicate.bom.metadata.timestamp)

exceeding = time.now_ns() - (timestamp + maximum_age)

allow {
	exceeding <= 0
}

reason = v {
	allow
	v := "SBOM is fresh enough"
}

reason = v {
	not allow
	v := "SBOM is too old"
}

errors[msg] {
	not input.evidence.predicate.bom.metadata.timestamp
	msg := "bom timestamp not presented"
}

violations = v{
	not allow
	v := [{"msg": sprintf("SBOM created at: %d (earliest create date is %d)", [timestamp, time.now_ns() - maximum_age])}]
}
