package typosentinel.policy

default violations := []

# Downgrade typosquat severity for same-group Maven with maintainer overlap
violations[{"message": sprintf("downgrade typosquat severity for same-group with maintainer overlap in %s", [input.package.name]), "severity": "info"}] {
  some t
  t := input.package.threats[_]
  t.type == "typosquatting"
  exists_signal(t.evidence, "same_group")
  exists_signal(t.evidence, "maintainer_overlap")
}

exists_signal(evs, name) {
  some i
  ev := evs[i]
  ev.type == "signal"
  ev.description == name
  ev.value == true
}

