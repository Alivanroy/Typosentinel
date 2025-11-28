# Malicious Package Indicators

Packages may include code or behaviors intended to exfiltrate data, execute unauthorized actions, or install persistence.

## Indicators
- Obfuscated install scripts or postinstall hooks
- Unauthorized network egress or credential access
- Unexpected process spawning or file writes

## Actions
- Remove immediately and rotate affected secrets
- Audit build artifacts and environments
- Report to the registry and upstream maintainers

