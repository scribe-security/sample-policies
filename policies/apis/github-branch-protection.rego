package verify

import future.keywords.in
import future.keywords.every

default allow := false

short_description = "Verify that built branch has branch protection rules set."

description = "Branch protection rules prevent unplanned and unmanged changes to the branch. It is recommended to set branch protection rules for all branches."

verify = v {
    api_status_code == 200
	v := {
		"allow": allow,
		"violation": {
			"type": "Branch Protection Violation",
			"details": violations,
		},
		"short_description": short_description,
		"description": description,
		"summary": [{
			"allow": allow,
			"reason": reason,
			"violations": count(violations),
		}],
	}
}

verify = v {
    api_status_code != 200
	v := {
		"allow": false,
		"violation": {
			"type": "Branch Protection Violation",
			"details": [{"api_status_code": api_status_code, "api_status": api_status}],
		},
		"short_description": short_description,
		"description": description,
		"summary": [{
			"allow": false,
			"reason": "api call failed",
			"violations": [{"api_status_code": api_status_code, "api_status": api_status}],
		}],
	}
}

reason = v {
	allow
	v := "all required branch protection rules are in place."
}

reason = v {
	not allow
	v := "found branch protection rules missing."
}

allow {
	count(violations) == 0
}


violations = j {
    field_exists("message", api_info)
    v = api_info[message]
    v == "Branch not protected"
    j:= [{ "branch protection enabled": false }]
}


violations = j {
    not field_exists("message", api_info)
	j := {r |
		some rule,expected in input.config.args.branch_protection_rules
        not check(rule, expected)
		r = {
			"branch protection rule": rule,
            "expected": expected,
            "found": get_result(rule),
			"result": check(rule, expected)
		}
	}
}

# Evaluations include true results, while violations only false
evaluate = v {
	v := {
		"allow": allow,
		"violation": {
			"type": "Branch Protection Violation",
			"details": evaluations,
		},
		"short_description": short_description,
		"description": description,
		"summary": [{
			"allow": allow,
			"reason": reason,
			"violations": count(evaluations),
		}],
	}
}

evaluations = j {
    not field_exists("message", api_info)
	j := {r |
		some rule,expected in input.config.args.branch_protection_rules
		r = {
			"branch protection rule": rule,
            "expected": expected,
            "found": get_result(rule),
			"result": check(rule, expected)
		}
	}
}

checkd(a,b) := r {
    r := {
        "rule" : a,
        "expected": b
    }
}

# Simple Rules

get_result("required_signatures") = r {
    t := object.get(api_info, ["required_signatures", "enabled"], false)
    r:= t
}

check("required_signatures", expected) := r {
    r:= get_result("required_signatures") == expected
}

get_result("enforce_admins") := r {
    t := object.get(api_info, ["enforce_admins", "enabled"], false)
    r:= t
}

check("enforce_admins", expected) := r {
    r:= get_result("enforce_admins") == expected
}

get_result("required_linear_history") := r {
    t := object.get(api_info, ["required_linear_history", "enabled"], false)
    r:= t
}

check("required_linear_history", expected) := r {
    r:= get_result("required_linear_history") == expected
}

# Note: allow force pushes == true is the less secure option
get_result("allow_force_pushes") := r {
    t := object.get(api_info, ["allow_force_pushes", "enabled"], false)
    r:= t
}

check("allow_force_pushes", expected) := r {
    r:= get_result("allow_force_pushes") == expected
}


# Note: allow deletions == true is the less secure option
get_result("allow_deletions") := r {
    t := object.get(api_info, ["allow_deletions", "enabled"], false)
    r:= t
}

check("allow_deletions", expected) := r {
    r:= get_result("allow_deletions") == expected
}

get_result("block_creations") := r {
    t := object.get(api_info, ["block_creations", "enabled"], false)
    r:= t
}

check("block_creations", expected) := r {
    r:= get_result("block_creations") == expected
}

get_result("required_conversation_resolution") := r {
    t := object.get(api_info, ["required_conversation_resolution", "enabled"], false)
    r:= t
}

check("required_conversation_resolution", expected) := r {
    r:= get_result("required_conversation_resolution") == expected
}

get_result("lock_branch") := r {
    t := object.get(api_info, ["lock_branch", "enabled"], false)
    r:= t
}

check("lock_branch", expected) := r {
    r:= get_result("lock_branch") == expected
}

get_result("allow_fork_syncing") := r {
    t := object.get(api_info, ["allow_fork_syncing", "enabled"], false)
    r:= t
}

check("allow_fork_syncing", expected) := r {
    r:= get_result("allow_fork_syncing") == expected
}

# Require Pull Request Related Rules

get_result("required_pull_request_reviews.dismiss_stale_reviews") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "dismiss_stale_reviews"], false)
    r:= t
}

check("required_pull_request_reviews.dismiss_stale_reviews", expected) := r {
    r:= get_result("required_pull_request_reviews.dismiss_stale_reviews") == expected
}

get_result("required_pull_request_reviews.required_approving_review_count") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "required_approving_review_count"], 0)
    r:= t
}

check("required_pull_request_reviews.required_approving_review_count", expected) := r {
    r:= get_result("required_pull_request_reviews.required_approving_review_count") == expected
}


get_result("required_pull_request_reviews.require_code_owner_reviews") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "require_code_owner_reviews"], false)
    r:= t
}

check("required_pull_request_reviews.require_code_owner_reviews", expected) := r {
    r:= get_result("required_pull_request_reviews.require_code_owner_reviews") == expected
}

get_result("required_pull_request_reviews.require_last_push_approval") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "require_last_push_approval"], false)
    r:= t
}

check("required_pull_request_reviews.require_last_push_approval", expected) := r {
    r:= get_result("required_pull_request_reviews.require_last_push_approval") == expected
}


get_result("required_pull_request_reviews.dismissal_restrictions.users") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "dismissal_restrictions", "teams"], [])
    r:= [ j | 
            i = t[_]
            i.type == "User"
            j := i["login"]
    ]
}

check("required_pull_request_reviews.dismissal_restrictions.users", expected) := r {
    r:= equal_arrays(get_result("required_pull_request_reviews.dismissal_restrictions.users"), expected)
}

get_result("required_pull_request_reviews.dismissal_restrictions.teams") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "dismissal_restrictions", "teams"], [])
    r:= [ j | 
            i = t[_]
            j := i["slug"]
    ]
}

check("required_pull_request_reviews.dismissal_restrictions.teams", expected) := r {
    r:= equal_arrays(get_result("required_pull_request_reviews.dismissal_restrictions.teams"), expected)
}


get_result("required_pull_request_reviews.dismissal_restrictions.apps") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "dismissal_restrictions", "teams"], [])
    r:= [ j | 
            i = t[_]
            j := i["slug"]
    ]
}

check("required_pull_request_reviews.dismissal_restrictions.apps", expected) := r {
    r:= equal_arrays(get_result("required_pull_request_reviews.dismissal_restrictions.apps"), expected)
}


get_result("required_pull_request_reviews.bypass_pull_request_allowances.users") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "bypass_pull_request_allowances", "users"], [])
    r:= [ j | 
            i = t[_]
            i.type == "User"
            j := i["login"]
    ]
}

check("required_pull_request_reviews.bypass_pull_request_allowances.users", expected) := r {
    r:= equal_arrays(get_result("required_pull_request_reviews.bypass_pull_request_allowances.users"), expected)
}

get_result("required_pull_request_reviews.bypass_pull_request_allowances.teams") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "bypass_pull_request_allowances", "teams"], [])
    r:= [ j | 
            i = t[_]
            j := i["slug"]
    ]
}

check("required_pull_request_reviews.bypass_pull_request_allowances.teams", expected) := r {
    r:= equal_arrays(get_result("required_pull_request_reviews.bypass_pull_request_allowances.teams"), expected)
}

get_result("required_pull_request_reviews.bypass_pull_request_allowances.apps") := r {
    t := object.get(api_info, ["required_pull_request_reviews", "bypass_pull_request_allowances", "teams"], [])
    r:= [ j | 
            i = t[_]
            j := i["slug"]
    ]
}

check("required_pull_request_reviews.bypass_pull_request_allowances.apps", expected) := r {
    r:= equal_arrays(get_result("required_pull_request_reviews.bypass_pull_request_allowances.apps"), expected)
}

# Restrictions Rules (who is allowed to push to matching branches)

get_result("restrictions.users") := r {
    t := object.get(api_info, ["restrictions", "users"], [])
    r:= [ j | 
            i = t[_]
            i.type == "User"
            j := i["login"]
    ]
}

check("restrictions.users", expected) := r {
    r:= equal_arrays(get_result("restrictions.users"), expected)
}


get_result("restrictions.teams") := r {
    t := object.get(api_info, ["restrictions", "teams"], [])
    r:= [ j | 
            i = t[_]
            j := i["slug"]
    ]
}

check("restrictions.teams", expected) := r {
    r:= equal_arrays(get_result("restrictions.teams"), expected)
}

get_result("restrictions.apps") := r {
    t := object.get(api_info, ["restrictions", "teams"], [])
    r:= [ j | 
            i = t[_]
            j := i["slug"]
    ]
}

check("restrictions.apps", expected) := r {
    r:= equal_arrays(get_result("restrictions.apps"), expected)
}

# Checks Rules
get_result("required_status_checks.strict") := r {
    t := object.get(api_info, ["required_status_checks", "strict"], false)
    r:= t
}

check("required_status_checks.strict", expected) := r {
    r:= get_result("required_status_checks.strict") == expected
}


get_result("required_status_checks.contexts") := r {
    t := object.get(api_info, ["required_status_checks", "contexts"], [])
    r:= t
}

check("required_status_checks.contexts", expected) := r {
    r:= equal_arrays(get_result("required_status_checks.contexts"), expected)
}

get_result("required_status_checks.checks") := r {
    t := object.get(api_info, ["required_status_checks", "contexts"], [])
    r:= t
}

check("required_status_checks.checks", expected) := r {
    r:= equal_arrays(get_result("required_status_checks.checks"), expected)
}

default equal_arrays(_,_) := false
equal_arrays(a, b) := true {
    count(a) == count(b)
    every i in a {
        every j in b {
            i == b[_]
            j == a[_]
        }
    }
}

api_url := sprintf("https://api.github.com/repos/%v/%v/branches/%v/protection", [input.config.args.owner, input.config.args.repo, input.config.args.branch])
query := {
    "method": "GET",
    "headers": { 
    "Accept": "application/vnd.github+json",
    "Authorization": concat("",["Bearer ", input.config.args.api_token]),
    "X-GitHub-Api-Version": "2022-11-28"
    },
    "url": api_url,
    "timeout": "30s",
}
response := http.send(query)
api_status_code := response.status_code
api_status := response.status
api_info := response.body

config := input.config.args.branch_protection_rules

field_exists(field, obj)  {
    _ = obj[field]
}
