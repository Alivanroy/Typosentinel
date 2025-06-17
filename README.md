# TypoSentinel

A comprehensive security tool for detecting typosquatting and malicious packages across multiple package managers.

## Features

- **Multi-language Support**: Analyzes packages from npm, PyPI, Go modules, Rust crates, Ruby gems, PHP Composer, Java Maven, and .NET NuGet
- **Advanced Detection**: Uses multiple analysis engines including static analysis, dynamic analysis, ML-based detection, and provenance verification
- **Typosquatting Detection**: Identifies packages that mimic popular legitimate packages
- **Supply Chain Security**: Comprehensive analysis of package dependencies and build processes
- **Multiple Output Formats**: JSON, YAML, text, and table formats for integration with CI/CD pipelines
- **Configurable Rules**: Customizable detection rules and thresholds
- **CLI Interface**: Command-line tool for scanning packages and dependencies

## Prerequisites

- Go 1.23 or higher

## Installation

### Build from Source

```bash
git clone https://github.com/Alivanroy/Typosentinel.git
cd typosentinel
go build -o typosentinel ./cmd/typosentinel
```

### Using Go Install

```bash
go install github.com/Alivanroy/Typosentinel/cmd/typosentinel@latest
```

## Configuration

Create a configuration file:

```yaml
# config.yaml
logging:
  level: "info"
  format: "json"

detection:
  static_analysis: true
  dynamic_analysis: true
  ml_analysis: true
  provenance_analysis: true

output:
  format: "json"  # json, yaml, text, table
  file: ""        # optional output file
```

## 🚀 Quick Start

### 1. Start the ML Service

```bash
cd ml/service
python api_server.py --host 0.0.0.0 --port 8000
```

### 2. Start the API Server

```bash
# Initialize configuration
./bin/typosentinel config init

# Start the server
./bin/typosentinel server --config config.yaml
```

### 3. Scan a Package

```bash
# Scan a single package
./bin/typosentinel scan package express --registry npm

# Scan from package.json
./bin/typosentinel scan file package.json

# Scan with custom options
./bin/typosentinel scan package react --registry npm --severity-threshold medium --output json
```

## Usage

### CLI Tool

#### Basic Package Scanning

```bash
# Scan a single package
./typosentinel scan --package "express" --registry npm

# Scan multiple packages
./typosentinel scan --packages "express,lodash,react" --registry npm

# Scan with custom threshold
./typosentinel scan --package "express" --registry npm --threshold 0.9

# Output to file
./typosentinel scan --package "express" --registry npm --output results.json
```

#### Dependency Analysis

```bash
# Scan project dependencies
./typosentinel scan --project-path ./my-project

# Scan specific dependency file
./typosentinel scan --dependency-file package.json
./typosentinel scan --dependency-file requirements.txt
./typosentinel scan --dependency-file go.mod
```

#### Output Formats

```bash
# JSON output (default)
./typosentinel scan --package "express" --format json

# YAML output
./typosentinel scan --package "express" --format yaml

# Table output
./typosentinel scan --package "express" --format table

# Text output
./typosentinel scan --package "express" --format text
```

#### Configuration

```bash
# Use custom config file
./typosentinel scan --config /path/to/config.yaml --package "express"

# Set log level
./typosentinel scan --package "express" --log-level debug

# Enable specific analysis engines
./typosentinel scan --package "express" --static --dynamic --ml --provenance
```

#### Configuration

```bash
# Initialize default configuration
typosentinel config init

# Show current configuration
typosentinel config show

# Validate configuration
typosentinel config validate
```

#### Version Information

```bash
# Show version
typosentinel version
```

#### Help and Documentation

```bash
# Show help
./typosentinel --help

# Show help for scan command
./typosentinel scan --help

# Show version
./typosentinel version
```

## Supported Package Managers

- **npm** - Node.js packages
- **PyPI** - Python packages  
- **Go Modules** - Go packages
- **Cargo** - Rust crates
- **RubyGems** - Ruby gems
- **Packagist** - PHP Composer packages
- **Maven** - Java packages
- **NuGet** - .NET packages

## Example Output

### JSON Format
```json
{
  "scan_id": "12345",
  "timestamp": "2024-01-15T10:30:00Z",
  "package": {
    "name": "express",
    "registry": "npm",
    "version": "4.18.2"
  },
  "results": {
    "risk_score": 0.2,
    "severity": "low",
    "issues": [],
    "similar_packages": [
      {
        "name": "expres",
        "similarity": 0.95,
        "risk": "high"
      }
    ]
  }
}
```

### Table Format
```
┌─────────────┬──────────┬────────────┬──────────────┐
│ Package     │ Registry │ Risk Score │ Severity     │
├─────────────┼──────────┼────────────┼──────────────┤
│ express     │ npm      │ 0.2        │ low          │
│ lodash      │ npm      │ 0.1        │ low          │
└─────────────┴──────────┴────────────┴──────────────┘
```

## Development

### Project Structure

```
.
├── cmd/                    # Application entry points
│   └── typosentinel/      # CLI application
├── internal/              # Private application code
│   ├── analyzer/          # Core scanning logic
│   ├── config/            # Configuration management
│   ├── detector/          # Detection algorithms
│   ├── dynamic/           # Dynamic analysis
│   ├── ml/                # ML-based detection
│   ├── provenance/        # Provenance analysis
│   ├── scanner/           # Main scanner logic
│   └── static/            # Static analysis
├── pkg/                   # Public packages
│   ├── npm/               # NPM registry support
│   ├── pypi/              # PyPI registry support
│   ├── golang/            # Go modules support
│   └── types/             # Common types
├── scripts/               # Build and deployment scripts
├── tests/                 # Test files
├── configs/               # Configuration files
└── docs/                  # Documentation
```

### Running Tests

```bash
# Run Go tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/detector/...
go test ./pkg/npm/...
```

### Building

```bash
# Build for current platform
go build -o typosentinel ./cmd/typosentinel

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o typosentinel-linux-amd64 ./cmd/typosentinel
GOOS=windows GOARCH=amd64 go build -o typosentinel-windows-amd64.exe ./cmd/typosentinel
GOOS=darwin GOARCH=amd64 go build -o typosentinel-darwin-amd64 ./cmd/typosentinel
```

## Docker Usage

```bash
# Build Docker image
docker build -t typosentinel .

# Run with Docker
docker run --rm -v $(pwd):/workspace typosentinel scan --project-path /workspace
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices and conventions
- Write comprehensive tests for new features
- Update documentation as needed
- Use meaningful commit messages
- Ensure code passes linting and tests

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Cobra CLI](https://github.com/spf13/cobra) - CLI framework
- [Viper](https://github.com/spf13/viper) - Configuration management
- [Logrus](https://github.com/sirupsen/logrus) - Structured logging

## Support

For support, please:

1. Check the [documentation](docs/)
2. Search [existing issues](https://github.com/Alivanroy/Typosentinel/issues)
3. Create a [new issue](https://github.com/Alivanroy/Typosentinel/issues/new)

## Roadmap

- [ ] Support for additional package registries
- [ ] Enhanced detection algorithms
- [ ] Integration with CI/CD pipelines
- [ ] Advanced configuration options
- [ ] Performance optimizations
- [ ] Integration with Large Language Models (LLMs) for advanced threat detection
- [ ] AI-powered package analysis and risk assessment
- [ ] Machine learning models for behavioral pattern recognition
- [ ] Natural language processing for package description analysis
- [ ] Automated threat intelligence gathering using AI

---

**TypoSentinel** - Protecting your software supply chain from typosquatting attacks.