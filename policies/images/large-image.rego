package verify
import future.keywords.if

default allow := false
default size := 10000000000

config := {
    "max_size" : 77808811
}


verify = v {
    v := {
        "allow": allow,
        "errors": errors,
        "summary": [{
            "allow": allow,
            "reason": sprintf("Image is too big, actual size is %d (max allowed size is %d)", [size, config.max_size])
        }]
    }
}

size = to_number(input.evidence.predicate.bom.components[j].properties[i]["value"]) {
    contains(input.evidence.predicate.bom.components[j]["bom-ref"], input.evidence.subject[k]["digest"]["sha256"])
    input.evidence.predicate.bom.components[j].properties[i]["name"] == "size"
}

allow {
    size <= config.max_size
}

errors[msg] {
    size == 10000000000
    msg := "image size not presented"
}