# TypoSentinel Makefile

# Go build parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet
GOFMT=gofmt
BINARY_NAME=typosentinel
BINARY_UNIX=$(BINARY_NAME)_unix
BINARY_WINDOWS=$(BINARY_NAME).exe
BINARY_DARWIN=$(BINARY_NAME)_darwin

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(shell git describe --tags --always --dirty) -X main.BuildTime=$(shell date -u '+%Y-%m-%d_%H:%M:%S') -s -w"
BUILD_FLAGS=-trimpath $(LDFLAGS)

# Directories
BUILD_DIR=build
DIST_DIR=dist
COVERAGE_DIR=coverage
DOCS_DIR=docs
TEST_DIR=test
INTEGRATION_DIR=test/integration
E2E_DIR=test/e2e
BENCH_DIR=test/benchmarks

# Cross-compilation targets
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64

# Test configuration
TEST_CONFIG=configs/test.yaml
TEST_TIMEOUT=10m
BENCH_TIME=10s
BENCH_COUNT=3
COVERAGE_THRESHOLD=80

# Variables
GO_FILES=$(shell find . -name '*.go' -not -path './temp/*' -not -path './artifacts/*' -not -path './reports/*')
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Default target
.PHONY: all
all: clean build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Cross-platform builds
.PHONY: build-all
build-all: clean
	@echo "Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		echo "Building for $$platform..."; \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		output_name=$(BINARY_NAME)-$(VERSION)-$$GOOS-$$GOARCH; \
		if [ $$GOOS = "windows" ]; then output_name=$$output_name.exe; fi; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH $(GOBUILD) $(BUILD_FLAGS) -o $(DIST_DIR)/$$output_name .; \
	done

# Create release archives
.PHONY: release
release: build-all
	@echo "Creating release archives..."
	@cd $(DIST_DIR) && for file in $(BINARY_NAME)-$(VERSION)-*; do \
		if [[ $$file == *".exe" ]]; then \
			zip $$file.zip $$file; \
		else \
			tar -czf $$file.tar.gz $$file; \
		fi; \
		sha256sum $$file > $$file.sha256; \
	done

# Quick release for current platform
.PHONY: release-local
release-local: build
	@echo "Creating local release..."
	@mkdir -p $(DIST_DIR)
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(DIST_DIR)/$(BINARY_NAME)-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH)
	@cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH).tar.gz $(BINARY_NAME)-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH)
	@cd $(DIST_DIR) && sha256sum $(BINARY_NAME)-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH) > $(BINARY_NAME)-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH).sha256

# Legacy build for multiple platforms (kept for compatibility)
.PHONY: build-legacy
build-legacy: clean
	@echo "Building for multiple platforms (legacy)..."
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 .
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe .

# Package binaries for release
.PHONY: package
package: build-all
	@echo "Creating release packages..."
	mkdir -p dist
	# Create tar.gz for Linux and macOS
	cd dist && tar -czf $(BINARY_NAME)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64
	cd dist && tar -czf $(BINARY_NAME)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64
	cd dist && tar -czf $(BINARY_NAME)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	# Create zip for Windows
	cd dist && zip $(BINARY_NAME)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	# Generate checksums (use shasum on macOS, sha256sum on Linux)
	cd dist && (shasum -a 256 *.tar.gz *.zip > checksums.sha256 2>/dev/null || sha256sum *.tar.gz *.zip > checksums.sha256)

# Test targets
.PHONY: test
test:
	@echo "Running unit tests..."
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) ./...

.PHONY: test-unit
test-unit:
	@echo "Running unit tests only..."
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) -short ./...

.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) -tags=integration ./$(INTEGRATION_DIR)/...

.PHONY: test-e2e
test-e2e:
	@echo "Running end-to-end tests..."
	$(GOTEST) -v -timeout=$(TEST_TIMEOUT) -tags=e2e ./$(E2E_DIR)/...

.PHONY: test-all
test-all:
	@echo "Running all tests..."
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) -tags="integration,e2e" ./...

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total | awk '{print "Total coverage: " $$3}'
	@echo "Coverage report generated: $(COVERAGE_DIR)/coverage.html"

.PHONY: test-coverage-ci
test-coverage-ci:
	@echo "Running tests with coverage for CI..."
	mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out

.PHONY: test-coverage-check
test-coverage-check:
	@echo "Checking coverage threshold..."
	@coverage=$$($(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ "$$coverage" -lt "$(COVERAGE_THRESHOLD)" ]; then \
		echo "Coverage $$coverage% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	else \
		echo "Coverage $$coverage% meets threshold $(COVERAGE_THRESHOLD)%"; \
	fi

.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	mkdir -p $(BENCH_DIR)
	$(GOTEST) -bench=. -benchmem -benchtime=$(BENCH_TIME) -count=$(BENCH_COUNT) ./... | tee $(BENCH_DIR)/benchmark.txt

.PHONY: benchmark-compare
benchmark-compare:
	@echo "Running benchmark comparison..."
	mkdir -p $(BENCH_DIR)
	$(GOTEST) -bench=. -benchmem -benchtime=$(BENCH_TIME) -count=$(BENCH_COUNT) ./... > $(BENCH_DIR)/new.txt
	@if [ -f $(BENCH_DIR)/old.txt ]; then \
		benchcmp $(BENCH_DIR)/old.txt $(BENCH_DIR)/new.txt; \
	else \
		echo "No previous benchmark results found"; \
	fi
	@cp $(BENCH_DIR)/new.txt $(BENCH_DIR)/old.txt

.PHONY: test-stress
test-stress:
	@echo "Running stress tests..."
	$(GOTEST) -v -race -timeout=30m -tags=stress ./...

.PHONY: test-memory
test-memory:
	@echo "Running memory tests..."
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) -memprofile=$(COVERAGE_DIR)/mem.prof ./...
	$(GOCMD) tool pprof -text $(COVERAGE_DIR)/mem.prof

.PHONY: test-cpu
test-cpu:
	@echo "Running CPU profiling tests..."
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) -cpuprofile=$(COVERAGE_DIR)/cpu.prof ./...
	$(GOCMD) tool pprof -text $(COVERAGE_DIR)/cpu.prof

.PHONY: test-race
test-race:
	@echo "Running race condition tests..."
	$(GOTEST) -v -race -timeout=$(TEST_TIMEOUT) ./...

.PHONY: test-fuzz
test-fuzz:
	@echo "Running fuzz tests..."
	$(GOTEST) -fuzz=. -fuzztime=30s ./...

.PHONY: test-clean
test-clean:
	@echo "Cleaning test artifacts..."
	rm -rf $(COVERAGE_DIR) $(BENCH_DIR) $(TEST_DIR)/tmp

.PHONY: test-watch
test-watch:
	@echo "Running tests in watch mode..."
	@command -v entr >/dev/null 2>&1 || { echo "entr is required for watch mode. Install with: brew install entr"; exit 1; }
	find . -name '*.go' | entr -c make test-unit

# Run performance tests
.PHONY: perf-test
perf-test:
	@echo "Running performance tests..."
	./tests/run_performance_tests.sh

# Comprehensive test automation
.PHONY: test-comprehensive
test-comprehensive: test-unit test-integration test-security test-e2e test-performance
	@echo "All comprehensive tests completed successfully"

.PHONY: test-security
test-security:
	@echo "Running security tests..."
	@go test -v -timeout=15m -run="TestSecurity" ./tests/

.PHONY: test-performance
test-performance:
	@echo "Running performance tests..."
	@go test -v -timeout=15m -run="TestAPIPerformanceBaseline|TestPackageAnalysisPerformance|TestBatchAnalysisPerformance" ./tests/

.PHONY: test-e2e
test-e2e:
	@echo "Running end-to-end tests..."
	@go test -v -timeout=20m -run="TestE2E" ./tests/

# CI/CD automation targets
.PHONY: ci-comprehensive
ci-comprehensive: lint test-comprehensive benchmark
	@echo "Comprehensive CI pipeline completed"

.PHONY: ci-quick-comprehensive
ci-quick-comprehensive: test-unit test-security
	@echo "Quick comprehensive CI pipeline completed"

# Code quality targets
.PHONY: lint
lint:
	@echo "Running golangci-lint..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is required. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run --config .golangci.yml

.PHONY: lint-fix
lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is required. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run --config .golangci.yml --fix

.PHONY: lint-verbose
lint-verbose:
	@echo "Running golangci-lint with verbose output..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is required. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run --config .golangci.yml -v

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .
	@command -v goimports >/dev/null 2>&1 && goimports -w . || echo "goimports not found, skipping import formatting"

.PHONY: fmt-check
fmt-check:
	@echo "Checking code formatting..."
	@unformatted=$$($(GOFMT) -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

.PHONY: vet
vet:
	@echo "Vetting code..."
	$(GOVET) ./...

.PHONY: staticcheck
staticcheck:
	@echo "Running staticcheck..."
	@command -v staticcheck >/dev/null 2>&1 || { echo "staticcheck is required. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1; }
	staticcheck ./...

.PHONY: gosec
gosec:
	@echo "Running gosec security scanner..."
	@command -v gosec >/dev/null 2>&1 || { echo "gosec is required. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; exit 1; }
	gosec ./...

.PHONY: govulncheck
govulncheck:
	@echo "Running govulncheck..."
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck is required. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

.PHONY: ineffassign
ineffassign:
	@echo "Running ineffassign..."
	@command -v ineffassign >/dev/null 2>&1 || { echo "ineffassign is required. Install with: go install github.com/gordonklaus/ineffassign@latest"; exit 1; }
	ineffassign ./...

.PHONY: misspell
misspell:
	@echo "Running misspell checker..."
	@command -v misspell >/dev/null 2>&1 || { echo "misspell is required. Install with: go install github.com/client9/misspell/cmd/misspell@latest"; exit 1; }
	misspell -error .

.PHONY: deadcode
deadcode:
	@echo "Running deadcode detector..."
	@command -v deadcode >/dev/null 2>&1 || { echo "deadcode is required. Install with: go install golang.org/x/tools/cmd/deadcode@latest"; exit 1; }
	deadcode ./...

.PHONY: quality
quality: fmt-check vet lint staticcheck gosec govulncheck ineffassign misspell
	@echo "All code quality checks passed!"

.PHONY: quality-fix
quality-fix: fmt lint-fix
	@echo "Code quality issues fixed!"

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

# CI/CD and development workflow targets
.PHONY: ci
ci: deps quality test-coverage test-coverage-check gosec govulncheck
	@echo "CI pipeline completed successfully!"

.PHONY: ci-quick
ci-quick: deps quality test-unit
	@echo "Quick CI pipeline completed successfully!"

.PHONY: pre-commit
pre-commit: quality test-unit
	@echo "Pre-commit checks passed!"

.PHONY: pre-push
pre-push: quality test-all test-coverage-check gosec govulncheck
	@echo "Pre-push checks passed!"

.PHONY: dev-tools
dev-tools:
	@echo "Installing development tools..."
	@command -v golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@command -v staticcheck >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@latest
	@command -v gosec >/dev/null 2>&1 || go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	@command -v ineffassign >/dev/null 2>&1 || go install github.com/gordonklaus/ineffassign@latest
	@command -v misspell >/dev/null 2>&1 || go install github.com/client9/misspell/cmd/misspell@latest
	@command -v deadcode >/dev/null 2>&1 || go install golang.org/x/tools/cmd/deadcode@latest
	@command -v goimports >/dev/null 2>&1 || go install golang.org/x/tools/cmd/goimports@latest
	@echo "Development tools installed!"

.PHONY: dev-clean
dev-clean: clean test-clean
	@echo "Cleaning development artifacts..."
	rm -rf .cache .tmp vendor
	$(GOCLEAN) -cache -testcache -modcache

.PHONY: dev-reset
dev-reset: dev-clean
	@echo "Resetting development environment..."
	$(GOMOD) download
	make dev-tools

.PHONY: release-check
release-check: quality test-all test-coverage-check gosec govulncheck benchmark
	@echo "Release checks completed successfully!"

.PHONY: release-build
release-build: clean release-check build-all docs
	@echo "Release build completed successfully!"
	@echo "Binaries available in $(DIST_DIR)/"
	@echo "Documentation available in $(DOCS_DIR)/"

# Production ready build - runs all checks and builds optimized binary
.PHONY: production
production: clean-all test lint security build
	@echo "Production build complete!"
	@echo "Binary: $(BINARY_NAME)"
	@echo "Ready for deployment"

# Help
.PHONY: help
help:
	@echo "Typosentinel Makefile - Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build           - Build the binary"
	@echo "  build-all       - Build for multiple platforms"
	@echo "  clean           - Clean build artifacts"
	@echo "  clean-all       - Clean all temporary files"
	@echo "  clean-production- Clean for production deployment"
	@echo ""
	@echo "Test targets:"
	@echo "  test            - Run unit tests"
	@echo "  test-unit       - Run unit tests only"
	@echo "  test-integration- Run integration tests"
	@echo "  test-e2e        - Run end-to-end tests"
	@echo "  test-all        - Run all tests"
	@echo "  test-coverage   - Run tests with coverage"
	@echo "  test-coverage-check - Check coverage threshold"
	@echo "  test-race       - Run race condition tests"
	@echo "  test-stress     - Run stress tests"
	@echo "  test-fuzz       - Run fuzz tests"
	@echo "  test-watch      - Run tests in watch mode"
	@echo "  test-clean      - Clean test artifacts"
	@echo "  benchmark       - Run benchmarks"
	@echo "  benchmark-compare - Compare benchmarks"
	@echo ""
	@echo "Code quality targets:"
	@echo "  quality         - Run all quality checks"
	@echo "  quality-fix     - Fix code quality issues"
	@echo "  lint            - Run golangci-lint"
	@echo "  lint-fix        - Run golangci-lint with auto-fix"
	@echo "  fmt             - Format code"
	@echo "  fmt-check       - Check code formatting"
	@echo "  vet             - Run go vet"
	@echo "  staticcheck     - Run staticcheck"
	@echo "  gosec           - Run security scanner"
	@echo "  govulncheck     - Run vulnerability checker"
	@echo ""
	@echo "Development targets:"
	@echo "  dev-setup       - Setup development environment"
	@echo "  dev-tools       - Install development tools"
	@echo "  dev-clean       - Clean development artifacts"
	@echo "  dev-reset       - Reset development environment"
	@echo "  pre-commit      - Run pre-commit checks"
	@echo "  pre-push        - Run pre-push checks"
	@echo ""
	@echo "CI/CD targets:"
	@echo "  ci              - Run full CI pipeline"
	@echo "  ci-quick        - Run quick CI pipeline"
	@echo "  release-check   - Run release checks"
	@echo "  release-build   - Build release"
	@echo "  production      - Production ready build with all checks"
	@echo ""
	@echo "Runtime targets:"
	@echo "  run             - Build and run the application"
	@echo "  install         - Install the binary"
	@echo "  health-check    - Check application health"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-run      - Build and run Docker container"
	@echo ""
	@echo "Utility targets:"
	@echo "  deps            - Install dependencies"
	@echo "  tidy            - Tidy dependencies"
	@echo "  security        - Run security scan"
	@echo "  docs            - Generate documentation"
	@echo "  perf-test       - Run performance tests"
	@echo "  help            - Show this help"