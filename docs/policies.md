# Policies Guide

## Overview
Typosentinel supports OPA/Rego policies to customize severity and gating. Policies are loaded from `policies.path` and can hot‑reload with `policies.hot_reload=true`.

## Ecosystem Examples

### NPM: Install Script Escalation
```rego
package typosentinel.policy

default violations := []

violations[{"message": sprintf("install scripts present in %s", [input.package.name]), "severity": "high"}] {
  some t
  t := input.package.threats[_]
  t.type == "install_script"
}
```

### PyPI: Obfuscation Limits
```rego
package typosentinel.policy

default violations := []

violations[{"message": sprintf("high obfuscation in %s", [input.package.name]), "severity": "high"}] {
  some t
  t := input.package.threats[_]
  t.type == "obfuscated_code"
}

violations[{"message": sprintf("suspicious patterns in %s", [input.package.name]), "severity": "medium"}] {
  some t
  t := input.package.threats[_]
  t.type == "suspicious_pattern"
}
```

### RubyGems: Eval‑Chain Thresholds
```rego
package typosentinel.policy

default violations := []

violations[{"message": sprintf("multiple eval chains in %s", [input.package.name]), "severity": "high"}] {
  some t
  t := input.package.threats[_]
  t.type == "suspicious_pattern"
}
```

## Binary Placement Severity
```rego
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

violations[{"message": sprintf("binary in non-legitimate path for %s", [input.package.name]), "severity": "high"}] {
  some t
  t := input.package.threats[_]
  t.type == "binary_detection"
  not contains(t.evidence[_].value, "node_modules")
  not contains(t.evidence[_].value, "build/")
}
```

## Typosquat Severity Downgrade
```rego
package typosentinel.policy

default violations := []

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
```

## Configuration Presets
- `policies.path`: directory containing `.rego` files
- `policies.hot_reload`: enable file watcher to reload policies
- `detector.registry.maven.same_group_similarity`: similarity threshold for same‑group gating
- `detector.registry.require_multi_signal.<registry>`: require multi‑signal gating per registry
- Content scanning presets: `scanner.content.*` keys

## Docker Examples
See DOCKER.md for examples using environment variables to set these configurations.
