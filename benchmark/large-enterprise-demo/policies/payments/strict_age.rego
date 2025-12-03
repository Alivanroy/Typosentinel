package typosentinel.policy

violations[{"message": msg, "severity": "high"}] {
  input.package.type == "new_package"
  # Parse age from evidence or description if available, or just block all "new_package" threats
  # For demo simplicity, we escalate severity of new_package threats
  msg := sprintf("Payments Policy Violation: New package detected (%s). All new packages must be vetted.", [input.package.name])
}
