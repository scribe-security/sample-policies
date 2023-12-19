package verify

default allow = false

default violations = []

short_description = "Verify that the Huggingface license is allowed"

verify = v {
	v := {
		"allow": allow,
		"violation": {
			"type": "Huggingface License Violation",
			"details": [{"hf_url": json.marshal(hf_url)}],
		},
		"short_description": short_description,
		"summary": [{
			"allow": allow,
			"reason": reason,
		}],
	}
}

allow {
	some l
	l = input.config.args.licenses[_]
	hf_info.cardData.license == l
}

reason = v {
	allow
	v := "Huggingface license is allowed"
}

reason = v {
	not allow
	v := "Huggingface license is not allowed"
}

hf_repo := repo {
	repo_url := input.evidence.predicate.bom.metadata.component.name
	r1 := replace(repo_url, "https://huggingface.co/", "")
	r2 := replace(r1, ".git", "")
	repo := r2
}

hf_url := concat("/", ["https://huggingface.co/api/models", hf_repo])

hf_info := info {
	query := {
		"method": "GET",
		"url": hf_url,
		"timeout": "30s",
	}
	info := http.send(query).body
}
