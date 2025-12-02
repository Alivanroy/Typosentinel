package typosentinel.policy

default violations := []

violations[{"message": sprintf("typosquat requires multi-signal gating for %s", [input.package.name])}] {
  some t
  t := input.package.threats[_]
  t.type == "typosquatting"
}

