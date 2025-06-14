# TypoSentinel Testing Guide

This guide explains how to test TypoSentinel locally, validate dependencies, and use the CLI tools effectively.

## Prerequisites

Before testing TypoSentinel, ensure you have the following installed:

### Required Dependencies

1. **Go 1.21+**
   ```bash
   # Install via Homebrew (macOS)
   brew install go
   
   # Or download from https://golang.org/dl/
   ```

2. **Python 3.11+**
   ```bash
   # Install via Homebrew (macOS)
   brew install python@3.11
   
   # Or download from https://python.org/downloads/
   ```

3. **Git**
   ```bash
   # Usually pre-installed on macOS
   git --version
   ```

### Optional Dependencies (for full functionality)

1. **Docker** (for containerized deployment)
   ```bash
   brew install --cask docker
   ```

2. **PostgreSQL** (for database functionality)
   ```bash
   brew install postgresql
   ```

3. **Redis** (for caching)
   ```bash
   brew install redis
   ```

## Installation and Setup

### 1. Clone and Build

```bash
# Navigate to project directory
cd /path/to/typosentinel

# Install Go dependencies
go mod download

# Build the CLI tool
go build -o bin/typosentinel ./cmd/typosentinel

# Or use Make
make build
```

### 2. Install Python Dependencies

```bash
# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install ML dependencies
pip install -r ml/requirements.txt
```

### 3. Configuration

```bash
# Initialize configuration
./bin/typosentinel config init

# View current configuration
./bin/typosentinel config show
```

## CLI Usage

### Basic Commands

#### 1. Check Dependencies

```bash
# Check all dependencies
./bin/typosentinel deps check

# List all dependencies
./bin/typosentinel deps list

# Install missing dependencies
./bin/typosentinel deps install
```

#### 2. Run Tests

```bash
# Run all tests
./bin/typosentinel test

# Run quick tests only
./bin/typosentinel test --quick

# Test ML components only
./bin/typosentinel test --ml-only

# Test database connectivity only
./bin/typosentinel test --db-only

# Run offline tests (no external dependencies)
./bin/typosentinel test --offline
```

#### 3. Scan Dependencies

```bash
# Scan current directory
./bin/typosentinel scan

# Scan specific directory
./bin/typosentinel scan ./my-project

# Scan specific file
./bin/typosentinel scan package.json

# Deep analysis with ML models
./bin/typosentinel scan --deep

# Include development dependencies
./bin/typosentinel scan --include-dev

# Output as JSON
./bin/typosentinel scan --output json

# Set custom threshold
./bin/typosentinel scan --threshold 0.9
```

#### 4. Check Individual Packages

```bash
# Check a specific package
./bin/typosentinel check "reqeusts"

# Check with detailed output
./bin/typosentinel check "eхpress" --detailed

# Check for specific registry
./bin/typosentinel check "lodash-utils" --registry npm

# Output as JSON
./bin/typosentinel check "suspicious-pkg" --output json
```

### Advanced Usage

#### Configuration Management

```bash
# Use custom config file
./bin/typosentinel --config ./custom-config.yaml scan

# Enable debug mode
./bin/typosentinel --debug scan

# Verbose output
./bin/typosentinel --verbose scan
```

#### Scanning Options

```bash
# Recursive directory scanning
./bin/typosentinel scan --recursive

# Exclude specific packages
./bin/typosentinel scan --exclude "lodash,express"

# Scan specific dependency types
./bin/typosentinel scan --type npm
./bin/typosentinel scan --type pip
./bin/typosentinel scan --type go
```

## Testing Scenarios

### 1. Local Development Testing

```bash
# Test basic functionality
./bin/typosentinel test --quick

# Test with sample malicious packages
./bin/typosentinel check "reqeusts"  # Should detect typo
./bin/typosentinel check "eхpress"   # Should detect homoglyph
./bin/typosentinel check "lodash"    # Should be clean
```

### 2. Integration Testing

```bash
# Test with real project dependencies
cd /path/to/your/project
/path/to/typosentinel/bin/typosentinel scan

# Test different output formats
./bin/typosentinel scan --output json > results.json
./bin/typosentinel scan --output html > results.html
```

### 3. Performance Testing

```bash
# Test with large dependency files
./bin/typosentinel scan /path/to/large/project --deep

# Benchmark scanning speed
time ./bin/typosentinel scan
```

### 4. ML Service Testing

```bash
# Start ML service
cd ml
python -m uvicorn service.api_server:app --host 0.0.0.0 --port 8000

# Test ML connectivity
./bin/typosentinel test --ml-only

# Test with ML-enabled scanning
./bin/typosentinel scan --deep
```

## Test Data and Examples

### Sample Malicious Packages

Test the detection system with these known typosquatting patterns:

```bash
# Typos
./bin/typosentinel check "reqeusts"     # requests
./bin/typosentinel check "beautifulsoup" # beautifulsoup4
./bin/typosentinel check "pillow"       # Pillow

# Homoglyphs (visually similar characters)
./bin/typosentinel check "eхpress"      # express (Cyrillic 'х')
./bin/typosentinel check "lodаsh"       # lodash (Cyrillic 'а')

# Dependency confusion
./bin/typosentinel check "lodash-utils"
./bin/typosentinel check "express-middleware"
```

### Sample Project Structures

Create test projects to validate scanning:

```bash
# Node.js project
mkdir test-npm && cd test-npm
echo '{
  "dependencies": {
    "express": "^4.18.0",
    "reqeusts": "^1.0.0"
  }
}' > package.json

# Python project
mkdir test-pip && cd test-pip
echo 'requests==2.28.0
beautifulsoup==1.0.0' > requirements.txt

# Go project
mkdir test-go && cd test-go
go mod init test-project
go get github.com/gin-gonic/gin
```

## Troubleshooting

### Common Issues

1. **Go not found**
   ```bash
   # Check Go installation
   go version
   
   # Add to PATH if needed
   export PATH=$PATH:/usr/local/go/bin
   ```

2. **Python dependencies missing**
   ```bash
   # Activate virtual environment
   source venv/bin/activate
   
   # Install dependencies
   pip install -r ml/requirements.txt
   ```

3. **Configuration errors**
   ```bash
   # Reset configuration
   rm ~/.typosentinel.yaml
   ./bin/typosentinel config init
   ```

4. **Permission errors**
   ```bash
   # Make binary executable
   chmod +x bin/typosentinel
   ```

### Debug Mode

```bash
# Enable debug logging
./bin/typosentinel --debug scan

# Check configuration
./bin/typosentinel config show

# Validate dependencies
./bin/typosentinel deps check
```

## Automated Testing

### Using Make

```bash
# Run all tests
make test

# Run specific test types
make test-unit
make test-integration
make test-ml

# Run with coverage
make test-coverage
```

### Using Scripts

```bash
# Run comprehensive tests
./scripts/test.sh

# Run quick tests
./scripts/test.sh --quick

# Run with specific coverage threshold
./scripts/test.sh --coverage 80
```

### CI/CD Testing

```bash
# Simulate CI environment
make ci

# Run security tests
make test-security

# Performance benchmarks
make test-performance
```

## Performance Benchmarks

### Expected Performance

- **Small projects** (< 50 dependencies): < 1 second
- **Medium projects** (50-200 dependencies): 1-5 seconds
- **Large projects** (200+ dependencies): 5-30 seconds
- **Deep analysis** (with ML): 2-10x slower

### Monitoring

```bash
# Monitor resource usage
top -p $(pgrep typosentinel)

# Memory usage
./bin/typosentinel scan --verbose 2>&1 | grep -i memory

# Timing analysis
time ./bin/typosentinel scan --deep
```

## Contributing to Tests

### Adding Test Cases

1. **Detection Tests**: Add to `internal/detector/detector_test.go`
2. **CLI Tests**: Add to `cmd/typosentinel/main_test.go`
3. **Integration Tests**: Add to `test/integration/`

### Test Data

1. **Malicious Packages**: Add to `test/data/malicious/`
2. **Legitimate Packages**: Add to `test/data/legitimate/`
3. **Sample Projects**: Add to `test/fixtures/`

### Running Specific Tests

```bash
# Run Go tests
go test ./...

# Run specific test package
go test ./internal/detector

# Run with coverage
go test -cover ./...

# Run Python tests
cd ml && python -m pytest
```

## Security Considerations

### Safe Testing

- Never install suspicious packages during testing
- Use isolated environments (containers/VMs)
- Validate test data before use
- Monitor network traffic during tests

### Test Environment Isolation

```bash
# Use Docker for isolated testing
docker build -t typosentinel-test .
docker run --rm -v $(pwd):/app typosentinel-test test

# Use virtual environments
python -m venv test-env
source test-env/bin/activate
```

This testing guide provides comprehensive coverage for validating TypoSentinel functionality in various scenarios and environments.