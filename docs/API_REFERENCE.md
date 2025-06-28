# TypoSentinel API Reference

This document provides a comprehensive reference for the TypoSentinel API and package interfaces.

## Table of Contents

- [REST API](#rest-api)
- [Core Packages](#core-packages)
- [Internal Packages](#internal-packages)
- [CLI Commands](#cli-commands)

## REST API

For detailed REST API documentation, see [API_DOCUMENTATION.md](API_DOCUMENTATION.md).

### Base URL
```
http://localhost:8080/api/v1
```

### Endpoints

- `GET /health` - Health check endpoint
- `POST /scan` - Scan packages for typosquatting
- `GET /scan/status/{id}` - Get scan status
- `GET /scan/results/{id}` - Get scan results

## Core Packages

### pkg/config

Configuration management for TypoSentinel.

#### Functions

- `Load(path string) (*Config, error)` - Load configuration from file
- `Validate(config *Config) error` - Validate configuration

### pkg/logger

Logging utilities with multiple output formats and levels.

#### Functions

- `New(config LoggerConfig) *Logger` - Create new logger instance
- `SetLevel(level string)` - Set logging level
- `Debug(msg string, fields ...interface{})` - Debug logging
- `Info(msg string, fields ...interface{})` - Info logging
- `Warn(msg string, fields ...interface{})` - Warning logging
- `Error(msg string, fields ...interface{})` - Error logging

### pkg/types

Common types and structures used throughout TypoSentinel.

#### Types

- `Package` - Represents a package to be analyzed
- `ScanResult` - Results of a typosquatting scan
- `ThreatLevel` - Enumeration of threat levels
- `Registry` - Package registry type (npm, pypi, etc.)

## Internal Packages

### internal/analyzer

Core analysis engine for detecting typosquatting patterns.

#### Key Functions

- `NewAnalyzer(config AnalyzerConfig) *Analyzer`
- `Analyze(pkg Package) (*AnalysisResult, error)`
- `GetSimilarPackages(name string) ([]string, error)`

### internal/detector

Detection engines for various typosquatting techniques.

#### Detectors

- `HomoglyphDetector` - Detects Unicode homoglyph attacks
- `EditDistanceDetector` - Detects packages with similar names
- `KeyboardLayoutDetector` - Detects keyboard layout-based typos
- `ReputationDetector` - Analyzes package reputation

### internal/ml

Machine learning components for advanced threat detection.

#### Components

- `BasicScorer` - Basic ML scoring algorithm
- `AdvancedScorer` - Advanced ML scoring with feature extraction
- `FeatureExtractor` - Extracts features from packages
- `ModelPipeline` - ML model pipeline management

### internal/scanner

Package scanning and analysis coordination.

#### Scanners

- `NPMScanner` - Scans npm packages
- `PyPIScanner` - Scans Python packages
- `GoScanner` - Scans Go modules
- `RubyScanner` - Scans Ruby gems
- `JavaScanner` - Scans Java packages

### internal/api/rest

REST API server implementation.

#### Components

- `Server` - Main API server
- `Middleware` - HTTP middleware components
- `Handlers` - Request handlers

### internal/database

Threat database management and updates.

#### Functions

- `NewThreatDB(config DBConfig) *ThreatDB`
- `UpdateThreats() error`
- `QueryThreats(criteria Criteria) ([]Threat, error)`

### internal/registry

Package registry clients for fetching package information.

#### Clients

- `NPMClient` - npm registry client
- `PyPIClient` - PyPI registry client
- `OptimizedClient` - Optimized registry client with caching

## CLI Commands

### Main Commands

- `typosentinel scan` - Scan packages for typosquatting
- `typosentinel serve` - Start the REST API server
- `typosentinel benchmark` - Run performance benchmarks
- `typosentinel train` - Train ML models

### Scan Command Options

```bash
typosentinel scan [flags] <package-name>

Flags:
  --registry string     Package registry (npm, pypi, go, ruby, java)
  --output string       Output format (json, yaml, table)
  --config string       Configuration file path
  --threshold float     Threat threshold (0.0-1.0)
  --verbose             Enable verbose output
```

### Serve Command Options

```bash
typosentinel serve [flags]

Flags:
  --host string         Host to bind to (default "localhost")
  --port int            Port to listen on (default 8080)
  --config string       Configuration file path
  --workers int         Number of worker goroutines (default 10)
  --timeout int         Request timeout in seconds (default 30)
```

## Configuration

For detailed configuration options, see the configuration files in the `config/` directory:

- `config.yaml` - Default configuration
- `config-optimized.yaml` - Performance-optimized configuration
- `config-full-detection.yaml` - Full detection capabilities

## Error Handling

All API functions return errors following Go conventions. HTTP API endpoints return structured error responses:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Package name is required",
    "details": {}
  }
}
```

## Performance Considerations

- Use connection pooling for database operations
- Enable caching for registry lookups
- Configure appropriate worker pool sizes
- Monitor memory usage for large scans

## Security

For security considerations and vulnerability reporting, see [SECURITY.md](../SECURITY.md).

---

*This documentation is automatically generated. For the most up-to-date information, refer to the source code and inline documentation.*