# Suspicious Package Behavior

This page explains how TypoSentinel identifies and reports suspicious behaviors in third‑party packages and what actions you should take when such behaviors are detected.

## Overview
Suspicious behavior refers to actions or characteristics in a package that may indicate malicious intent or unacceptable risk. These signals are heuristic and context‑dependent, and they complement known vulnerability data and typosquatting detection.

## Common Indicators
- Unexpected install/prepare scripts performing privileged operations
- Obfuscated or minified code shipped in source distributions
- Embedded credential access (e.g., reading SSH keys, environment secrets)
- Silent network calls to untrusted domains or IPs during build/runtime
- Process spawning or file system traversal outside expected scope
- Telemetry collection without disclosure or opt‑in
- Excessive or redundant dependencies with overlapping functionality

## How TypoSentinel Detects It
- Static inspection of manifest scripts and install hooks
- Pattern‑based scanning for dangerous APIs and persistence mechanisms
- Cross‑referencing package metadata against trusted registries
- Similarity analysis against known malicious packages and campaigns
- Optional supply‑chain graph context (transitive risk, depth, propagation)

## Response Guidance
1. Review the package’s source repository and issue tracker for intent and disclosures.
2. Verify publisher reputation and recent activity (e.g., ownership changes, releases).
3. Pin or downgrade to safe versions; prefer well‑maintained alternatives when feasible.
4. Isolate use behind sandbox/container; limit permissions and network egress.
5. Add allowlist rules only with clear justification and documented approvals.

## Reducing False Positives
- Build scripts may legitimately compile native modules or fetch assets.
- Minification is common in web packages; verify bundled source maps and licenses.
- Network calls to official registries or CDNs can be legitimate; validate domains.

## Reporting
If you believe a package is malicious:
- Remove it from builds and deployments.
- File an advisory with the ecosystem’s registry (e.g., npm, PyPI).
- Open an issue in the package repo with evidence.
- Share indicators with your security team and update internal allow/deny lists.

## References
- Supply chain security best practices (OWASP, CNCF SIG Security)
- Registry advisories (GitHub Advisories, OSV)
- Organization policies for third‑party software risk

