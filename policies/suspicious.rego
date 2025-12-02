package typosentinel.policy

default violations := []

violations[{"message": sprintf("suspicious patterns found in %s", [input.package.name])}] {
  some t
  t := input.package.threats[_]
  t.type == "suspicious_pattern"
}

