# TypoSentinel Architecture & Reference

This document provides a comprehensive overview of the TypoSentinel architecture, command-line interface, and feature set.

## 🏗️ System Architecture

TypoSentinel is built as a modular, CLI-first application designed for extensibility and performance.

```mermaid
graph TD
    CLI[CLI (Cobra)] --> Config[Configuration (Viper)]
    CLI --> Scanner[Scanner Engine]
    
    Scanner --> Detectors[Project Detectors]
    Scanner --> Analyzers[Dependency Analyzers]
    Scanner --> Policy[Policy Engine]
    
    Analyzers --> PM[Package Managers]
    
    Scanner --> ThreatEngine[Threat Detection Engine]
    
    ThreatEngine --> ML[ML Engine]
    ThreatEngine --> Heuristics[Heuristic Analyzers]
    ThreatEngine --> Content[Content Scanner]
    ThreatEngine --> Network[Static Network Analyzer]
    ThreatEngine --> Vuln[Vulnerability Scanner]
    
    Scanner --> Integrations[Integration Hub]
    
    Integrations --> Splunk[Splunk HEC]
    Integrations --> Slack[Slack]
    Integrations --> Webhook[Webhooks]
    Integrations --> Email[Email]
    
    Scanner --> Cache[Cache Layer (Redis/Mem)]
    Scanner --> Output[Output Formatter]
```

### Core Components

1.  **CLI Layer (`cmd/`)**: Handles user interaction, flag parsing, and command execution using Cobra.
2.  **Configuration (`internal/config/`)**: Manages configuration via files (YAML) and environment variables using Viper.
3.  **Scanner Engine (`internal/scanner/`)**: The core orchestrator that:
    *   Detects project types (Node.js, Python, Go, etc.)
    *   Extracts dependencies using language-specific analyzers.
    *   Orchestrates threat analysis.
4.  **Threat Detection Engine**:
    *   **ML Engine (`internal/ml/`)**: Machine learning models for anomaly detection.
    *   **Heuristics**: Rules-based detection for typosquatting (Levenshtein, Jaro-Winkler).
    *   **Content Scanner**: Scans file contents for secrets and suspicious patterns.
    *   **Static Network Analyzer**: Analyzes code for suspicious network calls.
5.  **Integration Hub (`internal/integrations/`)**: Manages external connections for alerting and logging.

## 💻 CLI Reference

### Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--config` | `-c` | Config file path | `$HOME/.planfinale.yaml` |
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--output` | `-o` | Output format (`json`, `yaml`, `table`, `futuristic`) | `futuristic` |

### Commands

#### `scan`

Scans a project directory for threats.

**Usage**: `typosentinel scan [path] [flags]`

**Analysis Flags**:
- `--deep`: Enable deep analysis (slower but more thorough).
- `--advanced`: Enable advanced analysis features (ML, behavioral).
- `--supply-chain`: Enable enhanced supply chain analysis (build integrity).
- `--check-vulnerabilities`: Enable vulnerability checking against databases.
- `--threshold <float>`: Similarity threshold for typosquatting detection (default `0.8`).
- `--include-dev`: Include development dependencies in the scan.
- `--recursive`: Enable recursive scanning for monorepos.
- `--workspace-aware`: Enable workspace-aware scanning.

**Targeting Flags**:
- `--file <path>`: Scan a specific manifest file.
- `--exclude <pkg1,pkg2>`: Comma-separated list of packages to exclude.
- `--package-manager <npm,pypi...>`: Limit scan to specific package managers.
- `--registry <npm|pypi...>`: Force a specific registry adapter.

**SBOM Flags**:
- `--sbom-format <spdx|cyclonedx>`: Generate SBOM in the specified format.
- `--sbom-output <path>`: Output path for the generated SBOM.

**Content Scanning Flags**:
- `--content-entropy-threshold <float>`: Override entropy threshold for secret detection.
- `--content-include <glob>`: Glob patterns to include in content scan.
- `--content-exclude <glob>`: Glob patterns to exclude from content scan.

#### `version`

Displays version information.

**Usage**: `typosentinel version`

## ⚙️ Configuration Reference

Configuration is typically stored in `config.yaml`.

### Key Sections

```yaml
# Application Settings
app:
  log_level: "info"
  max_workers: 10

# Scanning Defaults
scanner:
  max_concurrency: 10
  timeout: "30s"
  include_dev_deps: false
  registries:
    - enabled: true
      url: "https://registry.npmjs.org"

# Machine Learning
ml:
  enabled: true
  threshold: 0.7
  model_path: "./models"

# Integrations
integrations:
  enabled: true
  connectors:
    splunk:
      type: "splunk"
      settings:
        hec_url: "..."
        token: "..."
    slack:
      type: "slack"
      settings:
        webhook_url: "..."

# Policies
policies:
  fail_on_threats: true
  min_threat_level: "high"
```

## 🚀 Features

### 1. Multi-Language Support
Detects and analyzes dependencies for:
- **Node.js** (`package.json`, `yarn.lock`)
- **Python** (`requirements.txt`, `pyproject.toml`, `Pipfile`)
- **Go** (`go.mod`, `go.sum`)
- **Rust** (`Cargo.toml`)
- **Java** (`pom.xml`, `build.gradle`)
- **.NET** (`*.csproj`, `packages.config`)
- **Ruby** (`Gemfile`)
- **PHP** (`composer.json`)

### 2. Advanced Threat Detection
- **Typosquatting**: Identifies packages with names similar to popular ones using Levenshtein distance, Jaro-Winkler, and homoglyph analysis.
- **Brandjacking**: Detects unauthorized use of known brand names.
- **Dependency Confusion**: Checks for internal package names available on public registries.
- **Malicious Code**: Static analysis for obfuscated code, install scripts, and suspicious network calls.

### 3. Supply Chain Security
- **Build Integrity**: Verifies package checksums and signatures.
- **Maintainer Reputation**: Analyzes maintainer history and activity (where supported).
- **Package Age**: Flags extremely new packages as suspicious.

### 4. SBOM Generation
Generates Software Bill of Materials in standard formats:
- **SPDX** (v2.2/v2.3)
- **CycloneDX** (v1.4)

### 5. Integrations
- **Splunk**: Forward security events to Splunk HEC.
- **Slack**: Send real-time alerts to Slack channels.
- **Webhooks**: Generic webhook support for custom integrations.
- **Email**: SMTP-based email notifications.

### 6. Vulnerability Scanning
Integrates with vulnerability databases (OSV, NVD) to identify known CVEs in dependencies.
