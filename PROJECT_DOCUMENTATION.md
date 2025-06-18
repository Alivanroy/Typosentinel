# TypoSentinel Project Documentation

## Overview

TypoSentinel is a comprehensive CLI security tool designed to detect typosquatting and malicious packages across multiple package managers. After cleanup, the project focuses on core CLI functionality with a streamlined architecture.

## Project Structure

```
TypoSentinel/
├── .github/
│   └── workflows/             # GitHub Actions CI/CD
├── cmd/                       # CLI command definitions
│   ├── cmd.go                 # Main command setup and execution
│   ├── root.go                # Root command definition
│   └── scan.go                # Scan command implementation
├── internal/                  # Private application code
│   ├── analyzer/              # Core analysis orchestration
│   ├── config/                # Configuration management
│   ├── detector/              # Detection algorithms and logic
│   ├── dynamic/               # Dynamic analysis engine
│   ├── ml/                    # Machine learning detection
│   ├── provenance/            # Provenance verification
│   ├── scanner/               # Main scanning logic
│   └── static/                # Static analysis engine
├── pkg/                       # Public packages
│   ├── config/                # Configuration utilities
│   ├── logger/                # Logging utilities
│   └── types/                 # Common types and interfaces
├── scripts/                   # Build and deployment scripts
├── tests/                     # Test files (currently empty after cleanup)
├── config.yaml                # Default configuration file
├── go.mod                     # Go module definition
├── go.sum                     # Go module checksums
├── main.go                    # Application entry point
├── Dockerfile                 # Docker build configuration
├── Makefile                   # Build automation
├── PROJECT_DOCUMENTATION.md   # Comprehensive project documentation
└── README.md                  # Project overview and usage
```

## Core Components

### CLI Application (`cmd/typosentinel/`)
- Main entry point for the CLI tool
- Command-line argument parsing using Cobra
- Configuration loading and validation
- Output formatting and file handling

### Analysis Engines (`internal/`)

#### Scanner (`internal/scanner/`)
- Main orchestration logic
- Coordinates different analysis engines
- Manages scan lifecycle and results

#### Static Analysis (`internal/static/`)
- Package metadata analysis
- Dependency tree examination
- File structure analysis
- Manifest file validation

#### Dynamic Analysis (`internal/dynamic/`)
- Runtime behavior analysis
- Installation process monitoring
- Network activity detection
- File system changes tracking

#### ML Analysis (`internal/ml/`)
- Machine learning-based detection
- Pattern recognition
- Anomaly detection
- Similarity analysis

#### Provenance Analysis (`internal/provenance/`)
- Supply chain verification
- Build process validation
- Source code authenticity
- Signature verification

#### Detector (`internal/detector/`)
- Core detection algorithms
- Typosquatting identification
- Malicious pattern matching
- Risk scoring

### Package Registry Support (`pkg/`)

#### NPM (`pkg/npm/`)
- NPM registry API integration
- Package.json parsing
- Dependency resolution
- Version analysis

#### PyPI (`pkg/pypi/`)
- PyPI API integration
- Requirements.txt parsing
- Setup.py analysis
- Wheel file inspection

#### Go Modules (`pkg/golang/`)
- Go.mod parsing
- Module proxy integration
- Dependency graph analysis
- Version constraint handling

#### Common Types (`pkg/types/`)
- Shared data structures
- Interface definitions
- Common utilities
- Error types

## Key Features

### Multi-Registry Support
- NPM (Node.js packages)
- PyPI (Python packages)
- Go Modules (Go packages)
- Cargo (Rust crates)
- RubyGems (Ruby gems)
- Packagist (PHP Composer)
- Maven (Java packages)
- NuGet (.NET packages)

### Detection Capabilities
- Typosquatting detection using similarity algorithms
- Malicious package identification
- Supply chain security analysis
- Dependency confusion detection
- Behavioral analysis
- Provenance verification

### Output Formats
- JSON (structured data)
- YAML (human-readable structured)
- Table (formatted display)
- Text (simple output)

### Configuration
- YAML-based configuration
- Environment variable support
- Command-line flag overrides
- Flexible detection thresholds

## Usage Patterns

### Single Package Scanning
```bash
./typosentinel scan --package "express" --registry npm
```

### Project Dependency Scanning
```bash
./typosentinel scan --project-path ./my-project
```

### Batch Processing
```bash
./typosentinel scan --packages "express,lodash,react" --registry npm
```

### Custom Configuration
```bash
./typosentinel scan --config custom-config.yaml --package "express"
```

## Build and Deployment

### Local Build
```bash
go build -o typosentinel ./cmd/typosentinel
```

### Cross-Platform Build
```bash
GOOS=linux GOARCH=amd64 go build -o typosentinel-linux-amd64 ./cmd/typosentinel
GOOS=windows GOARCH=amd64 go build -o typosentinel-windows-amd64.exe ./cmd/typosentinel
GOOS=darwin GOARCH=amd64 go build -o typosentinel-darwin-amd64 ./cmd/typosentinel
```

### Docker Usage
```bash
docker build -t typosentinel .
docker run --rm -v $(pwd):/workspace typosentinel scan --project-path /workspace
```

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/detector/...
go test ./pkg/npm/...
go test ./internal/provenance/...

# Generate coverage profile
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out

# Get coverage summary
go tool cover -func=coverage.out
```

### Test Coverage Strategy

The project maintains comprehensive test coverage across all components:

#### Current Coverage Status

| Package | Coverage | Priority | Notes |
|---------|----------|----------|-------|
| `pkg/types` | 83.3% | High | Core type definitions |
| `pkg/logger` | 56.9% | Medium | Logging utilities |
| `internal/provenance` | 38.9% | High | Security-critical component |
| `pkg/config` | 0.0% | High | Needs immediate attention |
| `pkg/metrics` | 0.0% | Medium | Monitoring component |
| `internal/analyzer` | TBD | High | Core analysis engine |
| `internal/detector` | TBD | High | Detection algorithms |
| `internal/scanner` | TBD | High | Main scanning logic |

#### Coverage Targets

- **Security-Critical Components** (`internal/provenance`, `internal/detector`): 90%+
- **Core Logic** (`internal/analyzer`, `internal/scanner`): 85%+
- **Public APIs** (`pkg/*`): 90%+
- **CLI Commands** (`cmd/*`): 75%+
- **Utilities** (logging, config): 80%+

#### Coverage Reporting

```bash
# Generate comprehensive coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# View coverage summary
go tool cover -func=coverage.out

# Coverage by package
go test -cover ./pkg/types
go test -cover ./internal/provenance
go test -cover ./internal/analyzer

# Detailed coverage analysis
go test -covermode=count -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | sort -k3 -nr
```

#### Test Categories

1. **Unit Tests**: Individual function and method testing
2. **Integration Tests**: Component interaction testing
3. **End-to-End Tests**: Full workflow testing
4. **Performance Tests**: Benchmark and load testing
5. **Security Tests**: Vulnerability and edge case testing

#### Continuous Integration

Coverage is automatically tracked in CI/CD:
- Minimum coverage thresholds enforced
- Coverage reports generated for each PR
- Regression detection for coverage drops
- Integration with code quality tools
- Codecov integration for detailed coverage analytics
- Coverage artifacts uploaded to GitHub Actions

**CI Coverage Commands:**
```bash
# CI test command (with race detection)
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Python ML component coverage
cd ml && python -m pytest tests/ -v --cov=. --cov-report=html --cov-report=xml
```

**Coverage Monitoring:**
- **Codecov Dashboard**: Tracks coverage trends and identifies regressions
- **GitHub Actions Artifacts**: HTML coverage reports for detailed analysis
- **PR Comments**: Automatic coverage change notifications
- **Branch Protection**: Prevents merging if coverage drops below threshold

**Coverage Quality Gates:**
- New code must have >80% coverage
- Overall project coverage must not decrease
- Critical security components require >90% coverage
- Public API functions require >95% coverage

## Configuration Options

### Detection Settings
- `static_analysis`: Enable/disable static analysis
- `dynamic_analysis`: Enable/disable dynamic analysis
- `ml_analysis`: Enable/disable ML-based detection
- `provenance_analysis`: Enable/disable provenance verification

### Output Settings
- `format`: Output format (json, yaml, text, table)
- `file`: Output file path (optional)
- `verbose`: Verbose logging

### Logging Settings
- `level`: Log level (debug, info, warn, error)
- `format`: Log format (json, text)

## Security Considerations

- Input validation and sanitization
- Secure configuration management
- No hardcoded credentials
- Minimal external dependencies
- Safe file handling
- Network request validation

## Performance Characteristics

- Concurrent package analysis
- Efficient memory usage
- Configurable timeouts
- Rate limiting for registry APIs
- Caching for repeated requests

## Extensibility

### Adding New Package Managers
1. Implement registry interface in `pkg/`
2. Add detection logic in `internal/detector/`
3. Update configuration schema
4. Add tests and documentation

### Adding New Detection Algorithms
1. Implement algorithm in `internal/detector/`
2. Integrate with analysis engines
3. Add configuration options
4. Update scoring logic

### Adding New Output Formats
1. Implement formatter in CLI
2. Update command-line options
3. Add format validation
4. Update documentation

## Dependencies

### Core Dependencies
- `github.com/spf13/cobra`: CLI framework
- `github.com/spf13/viper`: Configuration management
- `github.com/sirupsen/logrus`: Structured logging
- `gopkg.in/yaml.v3`: YAML processing

### Analysis Dependencies
- Various registry-specific HTTP clients
- JSON/YAML parsing libraries
- Cryptographic libraries for verification

## Maintenance

### Regular Tasks
- Update dependencies
- Review security advisories
- Update detection rules
- Performance optimization
- Documentation updates

### Monitoring
- Error rate tracking
- Performance metrics
- Registry API health
- Detection accuracy

## Future Roadmap

### AI and Machine Learning Integration
- [ ] Integration with Large Language Models (LLMs) for advanced threat detection
- [ ] AI-powered package analysis and risk assessment
- [ ] Machine learning models for behavioral pattern recognition
- [ ] Natural language processing for package description analysis
- [ ] Automated threat intelligence gathering using AI

### Core Enhancements
- [ ] Support for additional package registries
- [ ] Enhanced detection algorithms
- [ ] Integration with CI/CD pipelines
- [ ] Advanced configuration options
- [ ] Performance optimizations

This documentation provides a comprehensive overview of the cleaned TypoSentinel project, focusing on its core CLI functionality and streamlined architecture.