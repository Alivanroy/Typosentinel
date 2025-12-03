# Release Notes v1.2.0 - Advanced Threat Detection

**Release Date**: 2025-12-03

## 🎯 Overview

This release transforms Typosentinel into the **only open-source tool** capable of detecting advanced supply chain attacks like SolarWinds and Shai-Hulud. We've implemented comprehensive build integrity monitoring and CI/CD infrastructure security analysis.

## 🆕 Major Features

### Phase 1: Build Integrity Monitoring

**Detects SolarWinds-style build compromise attacks**

#### 1. Dormancy Detection
- Identifies time-delayed malware activation (SUNBURST waited 12-14 days)
- Flags `setTimeout`/`setInterval` > 7 days
- Detects date-based activation conditionals
- **Threat Type**: `dormant_code`

#### 2. Build Artifact Scanner
- Scans build directories for unexpected binaries
- Magic byte detection (PE, ELF, Mach-O)
- SHA-256 hashing for verification
- Location-based severity (Critical for `/test/`, High for `node_modules`)
- **Threat Type**: `unexpected_binary`

#### 3. Signature Verifier
- Windows: PE Authenticode signature extraction
- macOS: codesign validation
- Flags unsigned, self-signed, and recently issued certificates (< 30 days)
- **Threat Type**: `untrusted_signature`

### Phase 2: CI/CD Infrastructure Monitoring

**Detects Shai-Hulud-style GitHub Actions abuse**

#### 1. GitHub Actions Security
- **Self-Hosted Runner Detection**: Flags `runs-on: self-hosted` (backdoor vector)
- **Code Injection Detection**: 6 patterns including:
  - `${{ github.event.discussion.body }}`
  - `${{ github.event.issue.title }}`
  - `${{ github.event.pull_request.body }}`
- **C2 Channel Detection**: Workflows triggered by Discussions/Issues
- **Threat Types**: `cicd_injection`, `self_hosted_runner`, `c2_channel`

#### 2. GitLab CI Security
- Unknown Docker registry detection
- Hardcoded secret detection in variables

## 📊 Impact

### Now Detects
✅ SolarWinds-style trojanized binaries  
✅ SUNBURST-style dormant malware  
✅ Shai-Hulud GitHub Actions backdoors  
✅ Workflow code injection vulnerabilities  
✅ CI/CD C2 channels  

### Competitive Advantage
Typosentinel is now the **only open-source tool** that can detect:
- GitHub Actions as a command-and-control channel
- Self-hosted runner backdoor registration
- Workflow injection vulnerabilities

## 🧪 Testing

### Benchmark Scenarios
- `benchmark/scenarios/shai-hulud`: Replicates Shai-Hulud 2.0 attack
- All existing scenarios (event-stream, ua-parser, etc.) continue to pass

### Unit Tests
- `internal/scanner/build_artifact_scanner_test.go`
- `internal/scanner/cicd_scanner_test.go`
- `internal/scanner/signature_verifier.go`

## 📦 New Files

### Core Implementation
- `internal/scanner/build_artifact_scanner.go`
- `internal/scanner/signature_verifier.go`
- `internal/scanner/cicd_scanner.go`
- `internal/scanner/content_scanner.go` (extended)

### Tests
- `internal/scanner/build_artifact_scanner_test.go`
- `internal/scanner/cicd_scanner_test.go`

### Benchmark Scenarios
- `benchmark/scenarios/shai-hulud/`

## 🔄 Breaking Changes
None - all changes are additive.

## 🐛 Bug Fixes
- Fixed dormancy detection regex patterns
- Improved YAML parsing for workflow files

## 📚 Documentation
- Updated README.md with Phase 1 and Phase 2 features
- Updated CHANGELOG.md
- Created comprehensive walkthrough documentation

## 🙏 Acknowledgments
This release is based on research into:
- SolarWinds supply chain attack (SUNBURST)
- Shai-Hulud 2.0 campaign analysis by GitGuardian

---

**Full Changelog**: https://github.com/Alivanroy/Typosentinel/compare/v1.1.0...v1.2.0
