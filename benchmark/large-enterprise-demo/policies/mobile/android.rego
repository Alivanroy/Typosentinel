package typosentinel.policy

violations[{"message": msg, "severity": "critical"}] {
  input.package.type == "binary_detection"
  # Check for dex files
  contains(input.package.description, ".dex")
  msg := sprintf("Mobile Policy: Android executable (.dex) detected in %s", [input.package.name])
}
