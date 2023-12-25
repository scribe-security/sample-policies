package verify

import future.keywords.in
import future.keywords.every

default allow := false

short_description = "Verify that the project has push rules set."

description = "Push rules prevent unplanned and unmanged changes to the project repository. It is recommended to set push rules for all projects."

verify = v {
    api_status_code == 200
	v := {
		"allow": allow,
		"violation": {
			"type": "Push Rules",
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
			"type": "Push Rules Setting Violation",
			"details": [{"api_status_code": api_status_code, "api_status": api_status}],
		},
		"short_description": short_description,
		"description": description,
		"summary": [{
			"allow": false,
			"reason": "api call failed",
			"violations": [{"api_status_code": api_status_code, "api_status": api_status, "api_raw_response": api_info}],
		}],
	}
}


reason = v {
	allow
	v := "all required push rules are in place."
}

reason = v {
	not allow
	v := "found push rules missing."
}

allow {
	count(violations) == 0
}


violations = j {
    api_info == null
    j:= [{ "push rules set": false }]
}


violations = j {
    api_info != null
	j := {r |
		some rule,expected in input.config.args.push_rule
        not check(rule, expected)
		r = {
			"push rule": rule,
            "expected": expected,
            "found": get_result(rule),
			"result": check(rule, expected)
		}
	}
}

evaluations = j {
    not field_exists("message", api_info)
	j := {r |
		some rule,expected in input.config.args.push_rule
        #not check(rule, expected)
		r = {
			"push rule": rule,
            "expected": expected,
            "found": get_result(rule),
			"result": check(rule, expected)
		}
	}
}


get_result("commit_message_regex") := r {
    t := object.get(api_info, ["commit_message_regex"], "")
    r:= t
}

check("commit_message_regex", expected) := r {
    r:= str_norm(get_result("commit_message_regex")) == str_norm(expected)
}

get_result("commit_message_negative_regex") := r {
    t := object.get(api_info, ["commit_message_negative_regex"], null)
    r:= t
}

check("commit_message_negative_regex", expected) := r {
    r:= str_norm(get_result("commit_message_negative_regex")) == str_norm(expected)
}

get_result("branch_name_regex") := r {
    t := object.get(api_info, ["branch_name_regex"], null)
    r:= t
}

check("branch_name_regex", expected) := r {
    r:= str_norm(get_result("branch_name_regex")) == str_norm(expected)
}

get_result("deny_delete_tag") := r {
    t := object.get(api_info, ["deny_delete_tag"], false)
    r:= t
}

check("deny_delete_tag", expected) := r {
    r:= get_result("deny_delete_tag") == expected
}

get_result("member_check") := r {
    t := object.get(api_info, ["member_check"], false)
    r:= t
}

check("member_check", expected) := r {
    r:= get_result("member_check") == expected
}

get_result("prevent_secrets") := r {
    t := object.get(api_info, ["prevent_secrets"], false)
    r:= t
}

check("prevent_secrets", expected) := r {
    r:= get_result("prevent_secrets") == expected
}

get_result("author_email_regex") := r {
    t := object.get(api_info, ["author_email_regex"], null)
    r:= t
}

check("author_email_regex", expected) := r {
    r:= str_norm(get_result("author_email_regex")) == str_norm(expected)
}

get_result("file_name_regex") := r {
    t := object.get(api_info, ["file_name_regex"], null)
    r:= t
}

check("file_name_regex", expected) := r {
    r:= str_norm(get_result("file_name_regex")) == str_norm(expected)
}

get_result("max_file_size") := r {
    t := object.get(api_info, ["max_file_size"], 0)
    r:= t
}

check("max_file_size", expected) := r {
    r:= get_result("max_file_size") == expected
}

get_result("commit_committer_check") := r {
    t := object.get(api_info, ["commit_committer_check"], null)
    r:= t
}

check("commit_committer_check", expected) := r {
    r:= get_result("commit_committer_check") == expected
}

get_result("reject_unsigned_commits") := r {
    t := object.get(api_info, ["reject_unsigned_commits"], null)
    r:= t
}

check("reject_unsigned_commits", expected) := r {
    r:= bool_norm(get_result("reject_unsigned_commits")) == bool_norm(expected)
}

str_norm(null) := r {
    r := ""
}

str_norm(s) := r {
    s != null
    r := s
}

bool_norm(null) := r {
    r := false
}

bool_norm(s) := r {
    s != null
    r := s
}

api_url := sprintf("https://gitlab.com/api/v4/projects/%v/push_rule", [input.config.args.project])
query := {
    "method": "GET",
    "headers": { 
            "Private-Token": input.config.args.api_token
    },
    "url": api_url,
    "timeout": "30s",
}
response := http.send(query)
api_status_code := response.status_code
api_status := response.status
api_info := response.body


config := input.config.args.push_rule

field_exists(field, obj)  {
    _ = obj[field]
}
