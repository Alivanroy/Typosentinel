# TypoSentinel

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](#)

TypoSentinel is an advanced typosquatting detection system that protects organizations from malicious packages in software supply chains. It combines multiple detection algorithms with machine learning to identify suspicious packages across various package registries.

## 🚀 Features

- **Multi-Registry Support**: NPM, PyPI, Go Modules, Cargo, RubyGems, Packagist
- **Advanced Detection Algorithms**:
  - Lexical similarity analysis (Levenshtein, Jaro-Winkler)
  - Homoglyph detection
  - Dependency confusion detection
  - Reputation-based analysis
- **Machine Learning Integration**: 
  - Semantic similarity models
  - Malicious package classification
  - Batch analysis capabilities
- **REST API**: Comprehensive API for integration
- **CLI Tool**: Command-line interface for scanning
- **Real-time Scanning**: Continuous monitoring capabilities
- **Policy Engine**: Customizable security policies
- **Database Storage**: PostgreSQL for persistence

## 📋 Prerequisites

- **Go**: 1.21 or higher
- **Python**: 3.8+ (for ML components)
- **PostgreSQL**: 12+ (for data storage)
- **Docker**: Optional, for containerized deployment

## 🛠️ Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/typosentinel/typosentinel.git
cd typosentinel

# Install Go dependencies
go mod download

# Install Python dependencies for ML components
cd ml
pip install -r requirements.txt
cd ..

# Build the application
go build -o bin/typosentinel cmd/typosentinel/main.go
```

### Using Docker

```bash
# Build the Docker image
docker build -t typosentinel .

# Run with Docker Compose
docker-compose up -d
```

## ⚙️ Configuration

Create a configuration file `config.yaml`:

```yaml
api:
  host: "localhost"
  port: 8080
  debug_mode: false
  read_timeout_seconds: 30
  write_timeout_seconds: 30
  idle_timeout_seconds: 60

database:
  host: "localhost"
  port: 5432
  name: "typosentinel"
  user: "postgres"
  password: "password"
  ssl_mode: "disable"
  max_connections: 25
  max_idle_connections: 5
  connection_max_lifetime_minutes: 30

ml_service:
  base_url: "http://localhost:8000"
  api_key: "your-ml-api-key"
  timeout_seconds: 30
  max_retries: 3

detection:
  similarity_threshold: 0.8
  homoglyph_threshold: 0.9
  reputation_threshold: 0.7
  max_suggestions: 10
  enable_ml_detection: true
  enable_reputation_check: true

registries:
  npm:
    base_url: "https://registry.npmjs.org"
    rate_limit_per_minute: 60
    timeout_seconds: 10
  pypi:
    base_url: "https://pypi.org"
    rate_limit_per_minute: 60
    timeout_seconds: 10
  go:
    base_url: "https://proxy.golang.org"
    rate_limit_per_minute: 60
    timeout_seconds: 10
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

## 📖 Usage

### CLI Commands

#### Scanning

```bash
# Scan a specific package
typosentinel scan package <package-name> --registry <registry>

# Scan from dependency file
typosentinel scan file <file-path>

# Scan with options
typosentinel scan package lodash \
  --registry npm \
  --severity-threshold high \
  --include-dev-dependencies \
  --output json \
  --output-file results.json
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

### REST API

#### Authentication

All API requests require an API key in the Authorization header:

```bash
curl -H "Authorization: Bearer your-api-key" \
     http://localhost:8080/api/v1/scan
```

#### Endpoints

##### Health Check

```bash
GET /health
```

##### Create Scan

```bash
POST /api/v1/scan
Content-Type: application/json

{
  "options": {
    "target": "package.json",
    "include_dev_dependencies": true,
    "severity_threshold": "medium",
    "max_depth": 3,
    "timeout_seconds": 300
  }
}
```

##### Get Scan Results

```bash
GET /api/v1/scan/{scan_id}
```

##### List Scans

```bash
GET /api/v1/scans?limit=20&offset=0
```

##### Find Similar Packages

```bash
POST /api/v1/ml/similarity
Content-Type: application/json

{
  "package_name": "express",
  "registry": "npm",
  "top_k": 10,
  "threshold": 0.7
}
```

##### Check Malicious Package

```bash
POST /api/v1/ml/malicious
Content-Type: application/json

{
  "package_name": "suspicious-package",
  "registry": "npm",
  "version": "1.0.0"
}
```

## 🧠 Machine Learning Components

TypoSentinel includes advanced ML models for enhanced detection:

### Semantic Similarity Model

- Uses sentence transformers for package name embeddings
- FAISS index for efficient similarity search
- Detects semantically similar package names

### Malicious Package Classifier

- Multi-modal feature extraction
- Random Forest and Isolation Forest ensemble
- Analyzes package metadata, dependencies, and patterns

### Starting ML Service

```bash
cd ml/service
python api_server.py --host 0.0.0.0 --port 8000 --workers 4
```

## 🗄️ Database Schema

TypoSentinel uses PostgreSQL with the following main tables:

- `organizations`: Organization management
- `users`: User accounts and roles
- `api_keys`: API key management
- `scan_requests`: Scan job tracking
- `scan_results`: Scan results storage
- `threats`: Detected threats
- `policies`: Security policies
- `package_metadata`: Package information cache
- `audit_logs`: Activity logging

## 🔧 Development

### Project Structure

```
.
├── cmd/                    # Application entry points
│   ├── server/            # API server
│   └── typosentinel/      # CLI application
├── internal/              # Private application code
│   ├── analyzer/          # Core scanning logic
│   ├── config/            # Configuration management
│   ├── database/          # Database layer
│   ├── detector/          # Detection algorithms
│   ├── ml/                # ML client
│   └── registry/          # Registry connectors
├── pkg/                   # Public packages
│   ├── api/               # REST API handlers
│   └── types/             # Shared types
├── ml/                    # Machine learning components
│   ├── models/            # ML model implementations
│   ├── service/           # ML API service
│   └── requirements.txt   # Python dependencies
├── scripts/               # Build and deployment scripts
├── test/                  # Test files
└── docs/                  # Documentation
```

### Running Tests

```bash
# Run Go tests
go test ./...

# Run with coverage
go test -cover ./...

# Run Python tests
cd ml
python -m pytest tests/
```

### Building

```bash
# Build for current platform
go build -o bin/typosentinel cmd/typosentinel/main.go

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o bin/typosentinel-linux-amd64 cmd/typosentinel/main.go
GOOS=windows GOARCH=amd64 go build -o bin/typosentinel-windows-amd64.exe cmd/typosentinel/main.go
GOOS=darwin GOARCH=amd64 go build -o bin/typosentinel-darwin-amd64 cmd/typosentinel/main.go
```

## 🐳 Docker Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  typosentinel-api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://postgres:password@db:5432/typosentinel
      - ML_SERVICE_URL=http://ml-service:8000
    depends_on:
      - db
      - ml-service

  ml-service:
    build: ./ml
    ports:
      - "8000:8000"
    environment:
      - PYTHONPATH=/app

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=typosentinel
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

## 📊 Monitoring and Logging

TypoSentinel provides comprehensive monitoring capabilities:

- Health check endpoints
- Structured logging with configurable levels
- Metrics collection (Prometheus compatible)
- Audit logging for security events
- Performance monitoring

## 🔒 Security

- API key authentication
- Rate limiting
- Input validation and sanitization
- SQL injection prevention
- Secure configuration management
- Audit logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices and conventions
- Write comprehensive tests
- Update documentation
- Use meaningful commit messages
- Ensure code passes linting and tests

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Levenshtein Distance Algorithm](https://en.wikipedia.org/wiki/Levenshtein_distance)
- [Jaro-Winkler Similarity](https://en.wikipedia.org/wiki/Jaro%E2%80%93Winkler_distance)
- [Sentence Transformers](https://www.sbert.net/)
- [FAISS](https://github.com/facebookresearch/faiss)
- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [Cobra CLI](https://github.com/spf13/cobra)

## 📞 Support

For support, please:

1. Check the [documentation](docs/)
2. Search [existing issues](https://github.com/typosentinel/typosentinel/issues)
3. Create a [new issue](https://github.com/typosentinel/typosentinel/issues/new)

## 🗺️ Roadmap

- [ ] Support for additional package registries
- [ ] Enhanced ML models with transformer architectures
- [ ] Real-time monitoring dashboard
- [ ] Integration with CI/CD pipelines
- [ ] Advanced policy engine with custom rules
- [ ] Kubernetes operator for deployment
- [ ] GraphQL API support
- [ ] Mobile application for monitoring

---

**TypoSentinel** - Protecting your software supply chain from typosquatting attacks.