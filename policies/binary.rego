package typosentinel.policy

default violations := []

violations[{"message": sprintf("binary in legitimate path for %s", [input.package.name]), "severity": "medium"}] {
  some t
  t := input.package.threats[_]
  t.type == "binary_detection"
  contains(t.evidence[_].value, "node_modules")
}

violations[{"message": sprintf("binary in build path for %s", [input.package.name]), "severity": "medium"}] {
  some t
  t := input.package.threats[_]
  t.type == "binary_detection"
  contains(t.evidence[_].value, "build/")
}

# High severity when binary detection without legitimate paths
violations[{"message": sprintf("binary in non-legitimate path for %s", [input.package.name]), "severity": "high"}] {
  some t
  t := input.package.threats[_]
  t.type == "binary_detection"
  not contains(t.evidence[_].value, "node_modules")
  not contains(t.evidence[_].value, "build/")
}
