# TypoSentinel Makefile
# Provides convenient commands for building, testing, and deploying TypoSentinel

# Variables
APP_NAME := typosentinel
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | awk '{print $$3}')

# Build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT) -X main.goVersion=$(GO_VERSION)"

# Directories
BIN_DIR := bin
COVERAGE_DIR := coverage
TEST_RESULTS_DIR := test-results
DIST_DIR := dist

# Go settings
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

# Docker settings
DOCKER_IMAGE := $(APP_NAME)
DOCKER_TAG := $(VERSION)
DOCKER_REGISTRY := # Set this to your registry

# Default target
.DEFAULT_GOAL := help

# Help target
.PHONY: help
help: ## Show this help message
	@echo "TypoSentinel Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Clean targets
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -rf $(TEST_RESULTS_DIR)
	rm -rf $(DIST_DIR)
	@echo "Clean completed"

.PHONY: clean-all
clean-all: clean ## Clean all artifacts including Docker images
	@echo "Cleaning Docker images..."
	docker image prune -f
	docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true
	@echo "Clean all completed"

# Setup targets
.PHONY: setup
setup: ## Setup development environment
	@echo "Setting up development environment..."
	@./scripts/deploy.sh setup --env development
	@echo "Setup completed"

.PHONY: deps
deps: ## Install dependencies
	@echo "Installing Go dependencies..."
	go mod download
	go mod tidy
	@echo "Installing Python dependencies..."
	cd ml && python3 -m pip install -r requirements.txt
	@echo "Dependencies installed"

# Build targets
.PHONY: build
build: $(BIN_DIR)/$(APP_NAME) $(BIN_DIR)/$(APP_NAME)-server ## Build binaries for current platform

.PHONY: build-enhanced
build-enhanced: $(BIN_DIR)/$(APP_NAME)-enhanced $(BIN_DIR)/$(APP_NAME)-worker $(BIN_DIR)/$(APP_NAME)-scanner ## Build enhanced server and workers

.PHONY: build-all-enhanced
build-all-enhanced: build build-enhanced ## Build all binaries including enhanced components

$(BIN_DIR)/$(APP_NAME): $(GO_FILES)
	@echo "Building $(APP_NAME) CLI..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) ./cmd/cli

$(BIN_DIR)/$(APP_NAME)-server: $(GO_FILES)
	@echo "Building $(APP_NAME) server..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-server ./cmd/server

$(BIN_DIR)/$(APP_NAME)-enhanced: $(GO_FILES)
	@echo "Building $(APP_NAME) enhanced server..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-enhanced ./cmd/enhanced-server

$(BIN_DIR)/$(APP_NAME)-worker: $(GO_FILES)
	@echo "Building $(APP_NAME) worker..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-worker ./cmd/worker

$(BIN_DIR)/$(APP_NAME)-scanner: $(GO_FILES)
	@echo "Building $(APP_NAME) scanner..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-scanner ./cmd/scanner

.PHONY: build-all
build-all: ## Build binaries for all platforms
	@echo "Building for all platforms..."
	@./scripts/build.sh all

.PHONY: build-linux
build-linux: ## Build binaries for Linux
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-linux-amd64 ./cmd/cli
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-server-linux-amd64 ./cmd/server

.PHONY: build-windows
build-windows: ## Build binaries for Windows
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/cli
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-server-windows-amd64.exe ./cmd/server

.PHONY: build-darwin
build-darwin: ## Build binaries for macOS
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/cli
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/cli
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-server-darwin-arm64 ./cmd/server

# Test targets
.PHONY: test
test: ## Run all tests
	@./scripts/test.sh all

.PHONY: test-unit
test-unit: ## Run unit tests only
	@./scripts/test.sh unit

.PHONY: test-integration
test-integration: ## Run integration tests only
	@./scripts/test.sh integration

.PHONY: test-api
test-api: ## Run API tests only
	@./scripts/test.sh api

.PHONY: test-ml
test-ml: ## Run ML service tests only
	@./scripts/test.sh ml

.PHONY: test-performance
test-performance: ## Run performance tests only
	@./scripts/test.sh performance

.PHONY: test-security
test-security: ## Run security tests only
	@./scripts/test.sh security

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	go test -v -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	go tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report generated: $(COVERAGE_DIR)/coverage.html"

# Linting targets
.PHONY: lint
lint: ## Run linting
	@./scripts/test.sh lint

.PHONY: lint-go
lint-go: ## Run Go linting only
	@echo "Running Go linting..."
	go vet ./...
	go fmt ./...
	if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, install from https://golangci-lint.run/usage/install/"; \
	fi

.PHONY: lint-python
lint-python: ## Run Python linting only
	@echo "Running Python linting..."
	cd ml && \
	if command -v flake8 >/dev/null 2>&1; then flake8 .; fi && \
	if command -v black >/dev/null 2>&1; then black --check .; fi

.PHONY: format
format: ## Format code
	@echo "Formatting Go code..."
	go fmt ./...
	@echo "Formatting Python code..."
	cd ml && if command -v black >/dev/null 2>&1; then black .; fi

# Development targets
.PHONY: dev
dev: build ## Start development environment
	@echo "Starting development environment..."
	@./scripts/deploy.sh deploy --env development

.PHONY: dev-server
dev-server: $(BIN_DIR)/$(APP_NAME)-server ## Start development server only
	@echo "Starting development server..."
	./$(BIN_DIR)/$(APP_NAME)-server --config config.yaml --debug

.PHONY: dev-ml
dev-ml: ## Start ML service only
	@echo "Starting ML service..."
	cd ml/service && python3 api_server.py --host 0.0.0.0 --port 8000

# Docker targets
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

.PHONY: docker-build-ml
docker-build-ml: ## Build ML service Docker image
	@echo "Building ML service Docker image..."
	docker build -t $(DOCKER_IMAGE)-ml:$(DOCKER_TAG) -f ml/Dockerfile ml/
	docker tag $(DOCKER_IMAGE)-ml:$(DOCKER_TAG) $(DOCKER_IMAGE)-ml:latest

.PHONY: docker-run
docker-run: docker-build ## Run Docker container
	@echo "Running Docker container..."
	docker run -p 8080:8080 -p 8000:8000 $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-compose-up
docker-compose-up: ## Start services with Docker Compose
	@echo "Starting services with Docker Compose..."
	docker-compose up -d

.PHONY: docker-compose-down
docker-compose-down: ## Stop services with Docker Compose
	@echo "Stopping services with Docker Compose..."
	docker-compose down

.PHONY: docker-compose-logs
docker-compose-logs: ## Show Docker Compose logs
	docker-compose logs -f

.PHONY: docker-push
docker-push: docker-build ## Push Docker image to registry
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "DOCKER_REGISTRY not set. Set it to push images."; \
		exit 1; \
	fi
	@echo "Pushing Docker image to $(DOCKER_REGISTRY)..."
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest

# Deployment targets
.PHONY: deploy
deploy: ## Deploy to production
	@echo "Deploying to production..."
	@./scripts/deploy.sh deploy --env production

.PHONY: deploy-dev
deploy-dev: ## Deploy to development
	@echo "Deploying to development..."
	@./scripts/deploy.sh deploy --env development

.PHONY: deploy-docker
deploy-docker: ## Deploy with Docker
	@echo "Deploying with Docker..."
	@./scripts/deploy.sh deploy --env docker

# Database targets
.PHONY: db-migrate
db-migrate: $(BIN_DIR)/$(APP_NAME)-server ## Run database migrations
	@echo "Running database migrations..."
	./$(BIN_DIR)/$(APP_NAME)-server migrate --config config.yaml

.PHONY: db-reset
db-reset: ## Reset database (WARNING: This will delete all data)
	@echo "WARNING: This will delete all data in the database!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Resetting database..."; \
		dropdb typosentinel 2>/dev/null || true; \
		createdb typosentinel; \
		make db-migrate; \
	else \
		echo "Database reset cancelled."; \
	fi

# Package targets
.PHONY: package
package: build-all ## Create release packages
	@echo "Creating release packages..."
	@./scripts/build.sh package

# Utility targets
.PHONY: version
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Go Version: $(GO_VERSION)"

.PHONY: info
info: ## Show build information
	@./scripts/build.sh info

.PHONY: status
status: ## Show service status
	@./scripts/deploy.sh status

.PHONY: logs
logs: ## Show service logs
	@./scripts/deploy.sh logs

.PHONY: health
health: ## Check service health
	@echo "Checking service health..."
	@if curl -f http://localhost:8080/health >/dev/null 2>&1; then \
		echo "✓ API service is healthy"; \
	else \
		echo "✗ API service is not responding"; \
	fi
	@if curl -f http://localhost:8000/health >/dev/null 2>&1; then \
		echo "✓ ML service is healthy"; \
	else \
		echo "✗ ML service is not responding"; \
	fi

# Install targets
.PHONY: install
install: build ## Install binaries to system
	@echo "Installing binaries..."
	cp $(BIN_DIR)/$(APP_NAME) /usr/local/bin/
	cp $(BIN_DIR)/$(APP_NAME)-server /usr/local/bin/
	@echo "Binaries installed to /usr/local/bin/"

.PHONY: uninstall
uninstall: ## Uninstall binaries from system
	@echo "Uninstalling binaries..."
	rm -f /usr/local/bin/$(APP_NAME)
	rm -f /usr/local/bin/$(APP_NAME)-server
	@echo "Binaries uninstalled"

# Documentation targets
.PHONY: docs
docs: ## Generate documentation
	@echo "Generating documentation..."
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Starting godoc server at http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "godoc not found. Install with: go install golang.org/x/tools/cmd/godoc@latest"; \
	fi

# Quick targets for common workflows
.PHONY: quick-test
quick-test: lint test-unit ## Quick test (lint + unit tests)

.PHONY: quick-build
quick-build: clean build test-unit ## Quick build and test

.PHONY: ci
ci: clean deps lint test build ## CI pipeline (clean, deps, lint, test, build)

.PHONY: release
release: clean deps lint test build-all package ## Full release pipeline

# Enhanced Server Docker targets
.PHONY: docker-build-enhanced
docker-build-enhanced: ## Build enhanced server Docker images
	@echo "Building enhanced server Docker images..."
	docker build -f Dockerfile.enhanced -t $(DOCKER_REGISTRY)$(APP_NAME)-enhanced:$(DOCKER_TAG) .
	docker build -f Dockerfile.enhanced -t $(DOCKER_REGISTRY)$(APP_NAME)-enhanced:latest .
	docker build -f Dockerfile.worker -t $(DOCKER_REGISTRY)$(APP_NAME)-worker:$(DOCKER_TAG) .
	docker build -f Dockerfile.worker -t $(DOCKER_REGISTRY)$(APP_NAME)-worker:latest .
	@echo "Enhanced server Docker images built"

.PHONY: docker-push-enhanced
docker-push-enhanced: ## Push enhanced server Docker images
	@echo "Pushing enhanced server Docker images..."
	docker push $(DOCKER_REGISTRY)$(APP_NAME)-enhanced:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)$(APP_NAME)-enhanced:latest
	docker push $(DOCKER_REGISTRY)$(APP_NAME)-worker:$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)$(APP_NAME)-worker:latest
	@echo "Enhanced server Docker images pushed"

# Enhanced Server deployment targets
.PHONY: dev-enhanced
dev-enhanced: ## Start enhanced development environment
	@echo "Starting enhanced development environment..."
	docker-compose -f docker-compose.enhanced.yml --profile development up -d
	@echo "Enhanced development environment started!"
	@echo "Enhanced Server: http://localhost:8080"
	@echo "Grafana: http://localhost:3001 (admin/admin)"
	@echo "Prometheus: http://localhost:9091"
	@echo "Kibana: http://localhost:5601"
	@echo "pgAdmin: http://localhost:5050"
	@echo "Redis Commander: http://localhost:8081"

.PHONY: prod-enhanced
prod-enhanced: ## Start enhanced production environment
	@echo "Starting enhanced production environment..."
	docker-compose -f docker-compose.enhanced.yml up -d
	@echo "Enhanced production environment started!"
	@echo "Load Balancer: http://localhost:80"
	@echo "Enhanced Server: http://localhost:8080"
	@echo "Monitoring: http://localhost:3001"

.PHONY: stop-enhanced
stop-enhanced: ## Stop enhanced environment
	@echo "Stopping enhanced environment..."
	docker-compose -f docker-compose.enhanced.yml down
	@echo "Enhanced environment stopped"

.PHONY: logs-enhanced
logs-enhanced: ## Show enhanced environment logs
	@echo "Showing enhanced environment logs..."
	docker-compose -f docker-compose.enhanced.yml logs -f

.PHONY: health-enhanced
health-enhanced: ## Check enhanced server health
	@echo "Checking enhanced server health..."
	@curl -s http://localhost:8080/health | jq . || echo "Enhanced server not responding"
	@curl -s http://localhost:8080/ready | jq . || echo "Enhanced server not ready"
	@docker-compose -f docker-compose.enhanced.yml ps

.PHONY: restart-enhanced
restart-enhanced: stop-enhanced ## Restart enhanced environment
	@sleep 5
	@$(MAKE) dev-enhanced

# Enhanced Server utilities
.PHONY: run-enhanced
run-enhanced: build-enhanced ## Run enhanced server locally
	@echo "Starting enhanced server locally..."
	./$(BIN_DIR)/$(APP_NAME)-enhanced

.PHONY: run-worker
run-worker: build-enhanced ## Run worker locally
	@echo "Starting worker locally..."
	./$(BIN_DIR)/$(APP_NAME)-worker

.PHONY: backup-enhanced
backup-enhanced: ## Create backup of enhanced environment
	@echo "Creating backup..."
	docker-compose -f docker-compose.enhanced.yml exec backup-service /app/scripts/backup.sh
	@echo "Backup completed"

.PHONY: migrate-enhanced
migrate-enhanced: ## Run database migrations for enhanced environment
	@echo "Running database migrations..."
	docker-compose -f docker-compose.enhanced.yml exec enhanced-server /app/scripts/migrate.sh
	@echo "Migrations completed"

# Watch targets (requires entr or similar)
.PHONY: watch
watch: ## Watch for changes and rebuild
	@if command -v entr >/dev/null 2>&1; then \
		echo "Watching for changes..."; \
		find . -name '*.go' | entr -r make build; \
	else \
		echo "entr not found. Install with: brew install entr (macOS) or apt-get install entr (Ubuntu)"; \
	fi

.PHONY: watch-test
watch-test: ## Watch for changes and run tests
	@if command -v entr >/dev/null 2>&1; then \
		echo "Watching for changes and running tests..."; \
		find . -name '*.go' | entr -r make test-unit; \
	else \
		echo "entr not found. Install with: brew install entr (macOS) or apt-get install entr (Ubuntu)"; \
	fi

# Phony targets to avoid conflicts with files
.PHONY: all build clean test lint format dev docker-build docker-run deploy