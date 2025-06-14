# TypoSentinel CLI Testing Guide

This guide demonstrates how to test the TypoSentinel CLI both locally and in Docker containers.

## 🚀 Quick Start

### Local Testing (Recommended)

1. **Build and test the CLI locally:**
   ```bash
   ./test_cli_local.sh
   ```

2. **Manual CLI testing:**
   ```bash
   # Build the CLI
   go build -o typosentinel-cli main.go
   
   # Test basic functionality
   ./typosentinel-cli --help
   ./typosentinel-cli scan --help
   ```

### Docker Testing

1. **Ensure Docker is running:**
   ```bash
   open -a Docker  # Start Docker Desktop on macOS
   docker info     # Verify Docker is running
   ```

2. **Run Docker tests:**
   ```bash
   ./test_cli_docker.sh
   ```

## 📋 CLI Commands Tested

### Basic Commands
- `./typosentinel-cli --help` - Show help information
- `./typosentinel-cli --version` - Show version information
- `./typosentinel-cli scan --help` - Show scan command help

### Package Scanning
- `./typosentinel-cli scan lodash` - Scan legitimate npm package
- `./typosentinel-cli scan expresss` - Scan potential typosquatting package
- `./typosentinel-cli scan requests --registry pypi` - Scan PyPI package
- `./typosentinel-cli scan axios --format json --save-report` - Scan with JSON output and save report

## 🔍 Test Results

### ✅ Working Features
1. **CLI Help System** - All help commands work correctly
2. **Package Scanning** - Successfully scans npm and PyPI packages
3. **JSON Output** - Generates structured JSON reports
4. **Report Saving** - Saves detailed reports to files
5. **Multiple Registries** - Supports npm, PyPI, and other registries
6. **ML Analysis** - Performs machine learning-based analysis
7. **Provenance Analysis** - Checks package provenance and integrity

### 📊 Sample Scan Results

The CLI successfully generates comprehensive reports including:
- **Package Information** - Name, version, registry
- **ML Analysis** - Similarity, malicious, reputation, and typosquatting scores
- **Feature Analysis** - Name entropy, length, character ratios
- **Risk Assessment** - Overall risk level and recommendations
- **Provenance Data** - Package integrity and source verification

### 📁 Generated Files

Scan reports are saved as JSON files with timestamps:
- `typosentinel-report-[timestamp].json`

Example report structure:
```json
{
  "package": {
    "name": "lodash",
    "version": "latest",
    "registry": "npm"
  },
  "ml_analysis": {
    "similarity_score": 0.3,
    "malicious_score": 0,
    "reputation_score": 0.72,
    "typosquatting_score": 0.176
  },
  "summary": {
    "total_findings": 2,
    "engines_used": ["ml", "provenance"],
    "status": "completed"
  }
}
```

## 🐳 Docker Configuration

### Dockerfile Features
- **Multi-stage build** - Optimized for production
- **Go application** - Builds main CLI and server binaries
- **Python ML service** - Includes machine learning components
- **Security** - Runs as non-root user
- **Health checks** - Built-in health monitoring

### Docker Commands
```bash
# Build image
docker build -t typosentinel:test .

# Run CLI commands
docker run --rm typosentinel:test ./typosentinel --help
docker run --rm typosentinel:test ./typosentinel scan lodash

# Run with volume for reports
docker run --rm -v $(pwd)/reports:/app/reports typosentinel:test ./typosentinel scan lodash --save-report
```

## 🧪 Test Scenarios

### 1. Legitimate Packages
- **lodash** (npm) - Popular utility library
- **requests** (PyPI) - HTTP library for Python
- **axios** (npm) - HTTP client for JavaScript

### 2. Potential Typosquatting
- **expresss** (extra 's') - Typosquatting attempt of 'express'
- **reqeusts** (misspelled) - Typosquatting attempt of 'requests'

### 3. Different Registries
- **npm** - Node.js packages
- **PyPI** - Python packages
- **Go modules** - Go packages

## 🔧 Troubleshooting

### Docker Issues
1. **Docker not running:**
   ```bash
   open -a Docker
   # Wait for Docker to start, then retry
   ```

2. **Build failures:**
   ```bash
   # Clean Docker cache
   docker system prune -f
   # Rebuild
   docker build --no-cache -t typosentinel:test .
   ```

### CLI Issues
1. **Build failures:**
   ```bash
   # Clean Go cache
   go clean -cache
   # Rebuild
   go build -o typosentinel-cli main.go
   ```

2. **Missing dependencies:**
   ```bash
   go mod tidy
   go mod download
   ```

## 📈 Performance Metrics

- **Scan Time** - Typically 30-100ms per package
- **Memory Usage** - ~50MB for CLI operations
- **Report Size** - 8-10KB JSON reports
- **Accuracy** - ML models provide confidence scores

## 🎯 Next Steps

1. **Enhanced Detection** - Improve typosquatting detection algorithms
2. **Real-time Scanning** - Add continuous monitoring capabilities
3. **Integration** - CI/CD pipeline integration
4. **Web Interface** - Browser-based scanning interface
5. **API Endpoints** - RESTful API for programmatic access

## 📞 Support

For issues or questions:
1. Check the logs in generated report files
2. Run with `--verbose` flag for detailed output
3. Use `--debug` flag for development debugging
4. Review the comprehensive test scripts provided