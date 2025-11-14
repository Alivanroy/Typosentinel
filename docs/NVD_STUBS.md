# NVD Feed Stubs

- Stubbed NVD feed provides representative CVE data for offline testing
- JSON schema validation ensures required fields are present
- Configurable mode: `stub` or `real` via feed config

## Configure
- update_interval: duration
- mode: `stub|real`

## Behavior
- Converts stub CVE records into internal `ThreatIntelligence` entries
- Validates keys: `id`, `description`, `published`, `severity`, `package{name,ecosystem}`, `references`

