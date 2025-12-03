package typosentinel.policy

# Platform team allows binaries if they are in bin/
# We suppress the default binary detection threat if it matches our allowlist

violations[{"message": msg, "severity": "medium"}] {
  input.package.type == "binary_detection"
  # Check if binary path is in bin/
  # This is a simplification; real policy would check evidence details
  not is_allowed_binary(input.package)
  msg := sprintf("Platform Policy: Unauthorized binary detected in %s", [input.package.name])
}

is_allowed_binary(pkg) {
  # Logic to check if binary is in bin/ (simulated)
  false # Default to false for demo to show detection
}
