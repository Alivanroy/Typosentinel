package typosentinel.policy

default violations := []

violations[{"message": sprintf("binary in legitimate path for %s: consider severity downgrade", [input.package.name])}] {
  some t
  t := input.package.threats[_]
  t.type == "binary_detection"
  contains(t.evidence[_].value, "node_modules")
}

violations[{"message": sprintf("binary in build path for %s: consider severity downgrade", [input.package.name])}] {
  some t
  t := input.package.threats[_]
  t.type == "binary_detection"
  contains(t.evidence[_].value, "build/")
}

