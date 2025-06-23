# TypoSentinel Project Structure

This document outlines the organization and structure of the TypoSentinel project.

## 📁 Root Directory Structure

```
TypoSentinel/
├── .github/                    # GitHub workflows and templates
├── cmd/                        # Application entry points
├── docs/                       # Project documentation
├── examples/                   # Usage examples and demos
├── internal/                   # Private application code
├── models/                     # ML models and training data
├── pkg/                        # Public packages and libraries
├── scripts/                    # Build and utility scripts
├── tests/                      # Test files and test data
├── web/                        # Web UI components
├── main.go                     # Main application entry point
├── go.mod                      # Go module definition
├── go.sum                      # Go module checksums
├── Makefile                    # Build automation
├── Dockerfile                  # Container configuration
├── README.md                   # Project overview and usage
├── LICENSE                     # MIT License
├── CONTRIBUTING.md             # Contribution guidelines
├── CODE_OF_CONDUCT.md          # Community guidelines
├── SECURITY.md                 # Security policy
├── CHANGELOG.md                # Version history
├── PROJECT_DOCUMENTATION.md    # Detailed documentation
├── config.yaml                 # Default configuration
├── config-*.yaml              # Environment-specific configs
└── .env.example               # Environment variables template
```

## 📂 Directory Details

### `/cmd` - Application Entry Points
Contains the main applications for this project.
- `typosentinel/` - CLI application
- Each subdirectory represents a different executable

### `/internal` - Private Application Code
Private application and library code. This is the code you don't want others importing.

```
internal/
├── analyzer/          # Core analysis logic
├── api/              # API server implementation
├── benchmark/        # Performance benchmarking
├── cache/            # Caching mechanisms
├── config/           # Configuration management
├── detector/         # Detection algorithms
├── ml/               # Machine learning components
├── optimization/     # Performance optimizations
├── registry/         # Package registry interfaces
├── reputation/       # Reputation analysis
├── scanner/          # Main scanning logic
└── vulnerability/    # Vulnerability database
```

### `/pkg` - Public Packages
Library code that's ok to use by external applications.

```
pkg/
├── logger/           # Logging utilities
├── metrics/          # Metrics collection
├── types/            # Common type definitions
└── utils/            # Utility functions
```

### `/docs` - Documentation
Project documentation beyond the main README.

```
docs/
├── API_DOCUMENTATION.md      # REST API reference
├── USER_GUIDE.md             # User guide
├── configuration.md          # Configuration reference
├── plugin_development_guide.md # Plugin development
└── architecture.md           # System architecture
```

### `/examples` - Examples and Demos
Example configurations and usage demonstrations.

```
examples/
├── basic/            # Basic usage examples
├── advanced/         # Advanced configuration examples
├── integrations/     # CI/CD integration examples
└── plugins/          # Plugin examples
```

### `/tests` - Test Files
Test files, test data, and testing utilities.

```
tests/
├── benchmark_test.go         # Benchmark tests
├── dataset_validator.go      # Test data validation
├── integration_test.go       # Integration tests
├── test-config.yaml         # Test configuration
└── testdata/                # Test data files
```

### `/scripts` - Build and Utility Scripts
Scripts for building, testing, and deployment.

```
scripts/
├── build.sh          # Build scripts
├── test.sh           # Test automation
├── deploy.sh         # Deployment scripts
└── setup.sh          # Development setup
```

### `/models` - ML Models
Machine learning models and training data.

```
models/
├── trained/          # Trained model files
├── training/         # Training scripts and data
└── evaluation/       # Model evaluation results
```

### `/web` - Web Interface
Web UI components and assets.

```
web/
├── static/           # Static assets (CSS, JS, images)
├── templates/        # HTML templates
└── components/       # Reusable UI components
```

## 🔧 Configuration Files

### Core Configuration
- `config.yaml` - Default application configuration
- `config-full-detection.yaml` - Full detection mode configuration
- `config-optimized.yaml` - Performance-optimized configuration
- `.env.example` - Environment variables template

### Development Configuration
- `.gitignore` - Git ignore rules
- `go.mod` / `go.sum` - Go module dependencies
- `Makefile` - Build automation
- `Dockerfile` - Container configuration

## 📋 Documentation Files

### Essential Documentation
- `README.md` - Project overview, installation, and quick start
- `PROJECT_DOCUMENTATION.md` - Comprehensive project documentation
- `PROJECT_STRUCTURE.md` - This file, project organization guide

### Legal and Community
- `LICENSE` - MIT License
- `CONTRIBUTING.md` - Contribution guidelines
- `CODE_OF_CONDUCT.md` - Community standards
- `SECURITY.md` - Security policy and reporting
- `CHANGELOG.md` - Version history and changes

## 🏗️ Build Artifacts

The following directories are created during build/runtime and should not be committed:

```
# Generated directories (in .gitignore)
temp/                 # Temporary files
artifacts/            # Build artifacts
reports/              # Generated reports
dist/                 # Distribution files
coverage/             # Test coverage reports
.cache/               # Cache files
```

## 🎯 File Naming Conventions

### Go Files
- `*_test.go` - Test files
- `*_benchmark_test.go` - Benchmark tests
- `main.go` - Main entry points
- `doc.go` - Package documentation

### Configuration Files
- `config*.yaml` - Configuration files
- `*.env*` - Environment files
- `Dockerfile*` - Container configurations

### Documentation
- `*.md` - Markdown documentation
- `README.md` - Primary documentation
- `CHANGELOG.md` - Version history
- `LICENSE` - License file (no extension)

## 🔄 Maintenance Guidelines

### Regular Cleanup
1. Remove unused dependencies from `go.mod`
2. Clean build artifacts: `make clean`
3. Update documentation when adding new features
4. Review and update `.gitignore` as needed

### Code Organization
1. Keep `internal/` packages focused and cohesive
2. Minimize dependencies between `internal/` packages
3. Use `pkg/` for reusable components
4. Document public APIs thoroughly

### Testing Structure
1. Unit tests alongside source code (`*_test.go`)
2. Integration tests in `/tests`
3. Benchmark tests for performance-critical code
4. Test data in `/tests/testdata`

## 📈 Growth Guidelines

As the project grows:

1. **New Features**: Add to appropriate `internal/` package
2. **New Executables**: Create new directory in `cmd/`
3. **Public APIs**: Consider adding to `pkg/`
4. **Documentation**: Update relevant docs and examples
5. **Configuration**: Add new config options to YAML files

---

*This structure follows Go project layout standards and best practices for maintainable, scalable codebases.*