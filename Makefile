# TypoSentinel Makefile

# Variables
BINARY_NAME=typosentinel
GO_FILES=$(shell find . -name '*.go' -not -path './temp/*' -not -path './artifacts/*' -not -path './reports/*')
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Default target
.PHONY: all
all: clean build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) .

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building for multiple platforms..."
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 .
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe .

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Run performance tests
.PHONY: perf-test
perf-test:
	@echo "Running performance tests..."
	./tests/run_performance_tests.sh

# Lint the code
.PHONY: lint
lint:
	@echo "Running linters..."
	go fmt ./...
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping advanced linting"; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Tidy dependencies
.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	go mod tidy

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f coverage.out coverage.html
	rm -f *.test *.prof

# Clean all temporary files and reports
.PHONY: clean-all
clean-all: clean
	@echo "Cleaning all temporary files..."
	rm -rf temp/ artifacts/ reports/
	rm -f *-report-*.json
	rm -rf *_test_results_*/
	rm -rf test-results/ coverage/ logs/
	rm -f *.log *.out *.html *.tmp
	rm -rf .coverage .coverage.*
	rm -f coverage.xml

# Production clean - removes all development artifacts
.PHONY: clean-production
clean-production: clean-all
	@echo "Cleaning for production deployment..."
	@echo "Removing development and test artifacts..."
	rm -rf tests/datasets/
	rm -f tests/validation_results.json
	rm -rf examples/
	rm -f .env.example
	@echo "Production clean complete"
	rm -f performance_test_*.txt security_test_*.txt

# Install the binary
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) .

# Run the application
.PHONY: run
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME)

# Development setup
.PHONY: dev-setup
dev-setup:
	@echo "Setting up development environment..."
	@if [ -f "scripts/dev-setup.sh" ]; then \
		./scripts/dev-setup.sh; \
	else \
		echo "Running basic setup..."; \
		go mod download; \
		go mod tidy; \
		echo "Development environment ready!"; \
	fi

# Project health check
.PHONY: health-check
health-check:
	@echo "Running project health check..."
	@if [ -f "scripts/health-check.sh" ]; then \
		./scripts/health-check.sh; \
	else \
		echo "Health check script not found"; \
		exit 1; \
	fi

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t typosentinel:$(VERSION) .

# Docker run
.PHONY: docker-run
docker-run: docker-build
	@echo "Running Docker container..."
	docker run --rm -it typosentinel:$(VERSION)

# Security scan
.PHONY: security
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed, install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	go doc -all > docs/API_REFERENCE.md

# Production ready build - runs all checks and builds optimized binary
.PHONY: production
production: clean-all test lint security build
	@echo "Production build complete!"
	@echo "Binary: $(BINARY_NAME)"
	@echo "Ready for deployment"

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build           - Build the binary"
	@echo "  build-all       - Build for multiple platforms"
	@echo "  test            - Run tests"
	@echo "  test-coverage   - Run tests with coverage"
	@echo "  benchmark       - Run benchmarks"
	@echo "  production      - Production ready build with all checks"
	@echo "  clean           - Clean build artifacts"
	@echo "  clean-all       - Clean all temporary files"
	@echo "  clean-production- Clean for production deployment"
	@echo "  perf-test    - Run performance tests"
	@echo "  lint         - Run linters"
	@echo "  fmt          - Format code"
	@echo "  tidy         - Tidy dependencies"
	@echo "  deps         - Install dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  clean-all    - Clean all temporary files"
	@echo "  install      - Install the binary"
	@echo "  run          - Build and run the application"
	@echo "  dev-setup    - Setup development environment"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Build and run Docker container"
	@echo "  security     - Run security scan"
	@echo "  docs         - Generate documentation"
	@echo "  help         - Show this help"