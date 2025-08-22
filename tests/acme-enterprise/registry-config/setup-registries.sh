#!/bin/bash

# Multi-Registry Environment Setup Script
# 
# This script configures multiple package registries (NPM, PyPI, Maven, NuGet, RubyGems, Go modules)
# with realistic dependencies and enterprise-grade configurations for Typosentinel testing.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REGISTRY_CONFIG_DIR="${SCRIPT_DIR}"
LOG_FILE="${SCRIPT_DIR}/registry-setup.log"

# Registry configurations
NPM_REGISTRY="https://registry.npmjs.org/"
PYPI_REGISTRY="https://pypi.org/simple/"
MAVEN_CENTRAL="https://repo1.maven.org/maven2/"
NUGET_REGISTRY="https://api.nuget.org/v3/index.json"
RUBYGEMS_REGISTRY="https://rubygems.org/"
GO_PROXY="https://proxy.golang.org/"

# Private registry configurations (for testing)
PRIVATE_NPM_REGISTRY="http://localhost:4873/"
PRIVATE_PYPI_REGISTRY="http://localhost:8080/simple/"
PRIVATE_MAVEN_REGISTRY="http://localhost:8081/repository/maven-public/"
PRIVATE_NUGET_REGISTRY="http://localhost:5000/v3/index.json"
PRIVATE_RUBYGEMS_REGISTRY="http://localhost:9292/"
PRIVATE_GO_PROXY="http://localhost:3000/"

# Logging functions
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_header() {
    echo -e "\n${PURPLE}=== $1 ===${NC}" | tee -a "$LOG_FILE"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system dependencies
check_dependencies() {
    log_header "Checking System Dependencies"
    
    local missing_deps=()
    
    # Check for Node.js and npm
    if ! command_exists node; then
        missing_deps+=("node")
    fi
    
    if ! command_exists npm; then
        missing_deps+=("npm")
    fi
    
    # Check for Python and pip
    if ! command_exists python3; then
        missing_deps+=("python3")
    fi
    
    if ! command_exists pip3; then
        missing_deps+=("pip3")
    fi
    
    # Check for Java and Maven
    if ! command_exists java; then
        missing_deps+=("java")
    fi
    
    if ! command_exists mvn; then
        missing_deps+=("mvn")
    fi
    
    # Check for .NET
    if ! command_exists dotnet; then
        log_warning ".NET SDK not found - NuGet configuration will be limited"
    fi
    
    # Check for Ruby and gem
    if ! command_exists ruby; then
        missing_deps+=("ruby")
    fi
    
    if ! command_exists gem; then
        missing_deps+=("gem")
    fi
    
    # Check for Go
    if ! command_exists go; then
        missing_deps+=("go")
    fi
    
    # Check for Docker (optional)
    if ! command_exists docker; then
        log_warning "Docker not found - private registry setup will be limited"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing critical dependencies: ${missing_deps[*]}"
        log_info "Please install the missing dependencies and try again."
        return 1
    fi
    
    log_success "All critical dependencies are available"
    return 0
}

# Setup directory structure
setup_directories() {
    log_header "Setting Up Directory Structure"
    
    # Create registry configuration directories
    mkdir -p "${REGISTRY_CONFIG_DIR}/npm"
    mkdir -p "${REGISTRY_CONFIG_DIR}/pypi"
    mkdir -p "${REGISTRY_CONFIG_DIR}/maven"
    mkdir -p "${REGISTRY_CONFIG_DIR}/nuget"
    mkdir -p "${REGISTRY_CONFIG_DIR}/rubygems"
    mkdir -p "${REGISTRY_CONFIG_DIR}/go"
    mkdir -p "${REGISTRY_CONFIG_DIR}/private-registries"
    mkdir -p "${REGISTRY_CONFIG_DIR}/certificates"
    mkdir -p "${REGISTRY_CONFIG_DIR}/logs"
    
    log_success "Directory structure created"
}

# Configure NPM registry
setup_npm_registry() {
    log_header "Configuring NPM Registry"
    
    local npm_config="${REGISTRY_CONFIG_DIR}/npm/.npmrc"
    
    # Create NPM configuration
    cat > "$npm_config" << EOF
# NPM Registry Configuration for ACME Enterprise
# Generated on $(date)

# Primary registry
registry=${NPM_REGISTRY}

# Scoped registries for internal packages
@acme:registry=${PRIVATE_NPM_REGISTRY}
@internal:registry=${PRIVATE_NPM_REGISTRY}
@company:registry=${PRIVATE_NPM_REGISTRY}

# Security settings
audit-level=moderate
fund=false

# Cache settings
cache=${REGISTRY_CONFIG_DIR}/npm/.npm-cache
cache-max=86400000
cache-min=10

# Proxy settings (if needed)
# proxy=http://proxy.company.com:8080
# https-proxy=http://proxy.company.com:8080

# Authentication (placeholder)
# //registry.npmjs.org/:_authToken=\${NPM_TOKEN}
# //${PRIVATE_NPM_REGISTRY}:_authToken=\${PRIVATE_NPM_TOKEN}

# Package-lock settings
package-lock=true
package-lock-only=false

# Install settings
save=true
save-exact=false
save-prefix=^

# Logging
loglevel=warn
progress=true

# Security
strict-ssl=true
ca[]=-----BEGIN CERTIFICATE-----
# Add your corporate CA certificates here
-----END CERTIFICATE-----
EOF

    # Create package.json template for testing
    cat > "${REGISTRY_CONFIG_DIR}/npm/package-template.json" << EOF
{
  "name": "@acme/test-package",
  "version": "1.0.0",
  "description": "Test package for registry configuration",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "security-scan": "npm audit --audit-level high"
  },
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21",
    "axios": "^1.6.0",
    "jsonwebtoken": "^9.0.2",
    "bcrypt": "^5.1.1"
  },
  "devDependencies": {
    "eslint": "^8.50.0",
    "jest": "^29.7.0",
    "nodemon": "^3.0.1",
    "prettier": "^3.0.3"
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/acme/test-package.git"
  },
  "keywords": ["acme", "enterprise", "test"],
  "author": "ACME Enterprise Security Team",
  "license": "MIT",
  "private": true
}
EOF

    # Create npm security configuration
    cat > "${REGISTRY_CONFIG_DIR}/npm/audit-config.json" << EOF
{
  "auditLevel": "moderate",
  "skipUnusedDependencies": false,
  "showFound": true,
  "allowedVulnerabilities": [],
  "excludePackages": [],
  "reportFormat": "json",
  "outputFile": "${REGISTRY_CONFIG_DIR}/logs/npm-audit.json"
}
EOF

    log_success "NPM registry configuration completed"
}

# Configure PyPI registry
setup_pypi_registry() {
    log_header "Configuring PyPI Registry"
    
    local pip_config="${REGISTRY_CONFIG_DIR}/pypi/pip.conf"
    
    # Create pip configuration
    cat > "$pip_config" << EOF
# PyPI Registry Configuration for ACME Enterprise
# Generated on $(date)

[global]
# Primary index
index-url = ${PYPI_REGISTRY}

# Additional indexes for internal packages
extra-index-url = ${PRIVATE_PYPI_REGISTRY}

# Trusted hosts
trusted-host = pypi.org
               pypi.python.org
               files.pythonhosted.org
               localhost

# Cache settings
cache-dir = ${REGISTRY_CONFIG_DIR}/pypi/.pip-cache

# Security settings
require-hashes = false
verify-ssl = true

# Proxy settings (if needed)
# proxy = http://proxy.company.com:8080

# Timeout settings
timeout = 60
retries = 3

# Install settings
user = false
no-deps = false
ignore-installed = false

[install]
# Install options
find-links = ${REGISTRY_CONFIG_DIR}/pypi/wheels
no-index = false
prefer-binary = true

# Upgrade strategy
upgrade-strategy = only-if-needed

[freeze]
# Freeze options
all = false
exclude-editable = false

[list]
# List options
format = columns
verbose = false
EOF

    # Create requirements template
    cat > "${REGISTRY_CONFIG_DIR}/pypi/requirements-template.txt" << EOF
# ACME Enterprise Python Dependencies
# Generated on $(date)

# Web frameworks
Flask==2.3.3
Django==4.2.7
FastAPI==0.104.1

# HTTP clients
requests==2.31.0
httpx==0.25.1

# Data processing
numpy==1.24.4
pandas==2.1.3
scikit-learn==1.3.2

# Database
SQLAlchemy==2.0.23
psycopg2-binary==2.9.9
PyMongo==4.6.0

# Security
cryptography==41.0.7
PyJWT==2.8.0
bcrypt==4.1.1

# Utilities
click==8.1.7
python-dotenv==1.0.0
celery==5.3.4

# Development
pytest==7.4.3
black==23.11.0
flake8==6.1.0
mypy==1.7.1

# Internal packages (examples)
# acme-auth-service==1.2.3
# acme-payment-gateway==2.1.0
# acme-user-management==1.5.2
EOF

    # Create Python security configuration
    cat > "${REGISTRY_CONFIG_DIR}/pypi/safety-config.json" << EOF
{
  "ignore": [],
  "output": "json",
  "full-report": true,
  "cache": true,
  "audit-and-monitor": true,
  "continue-on-error": false,
  "policy-file": "${REGISTRY_CONFIG_DIR}/pypi/safety-policy.json"
}
EOF

    # Create safety policy
    cat > "${REGISTRY_CONFIG_DIR}/pypi/safety-policy.json" << EOF
{
  "version": "2.0",
  "scan": {
    "ignore-cvss-severity-below": 7.0,
    "ignore-cvss-unknown-severity": false,
    "ignore-unpinned-requirements": false
  },
  "report": {
    "dependency-vulnerabilities": true,
    "security-updates": true,
    "ignore-environment": false
  },
  "security-updates": {
    "auto-security-updates-limit": 5,
    "dependency-vulnerability-auto-update": true
  }
}
EOF

    log_success "PyPI registry configuration completed"
}

# Configure Maven registry
setup_maven_registry() {
    log_header "Configuring Maven Registry"
    
    local maven_settings="${REGISTRY_CONFIG_DIR}/maven/settings.xml"
    
    # Create Maven settings
    cat > "$maven_settings" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!-- Maven Settings for ACME Enterprise -->
<!-- Generated on $(date) -->
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              http://maven.apache.org/xsd/settings-1.0.0.xsd">

  <!-- Local repository -->
  <localRepository>${REGISTRY_CONFIG_DIR}/maven/.m2/repository</localRepository>

  <!-- Proxy settings (if needed) -->
  <!--
  <proxies>
    <proxy>
      <id>corporate-proxy</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>proxy.company.com</host>
      <port>8080</port>
      <nonProxyHosts>localhost|127.0.0.1|*.company.com</nonProxyHosts>
    </proxy>
  </proxies>
  -->

  <!-- Server authentication -->
  <servers>
    <server>
      <id>central</id>
      <username>\${env.MAVEN_CENTRAL_USERNAME}</username>
      <password>\${env.MAVEN_CENTRAL_PASSWORD}</password>
    </server>
    <server>
      <id>acme-private</id>
      <username>\${env.ACME_MAVEN_USERNAME}</username>
      <password>\${env.ACME_MAVEN_PASSWORD}</password>
    </server>
  </servers>

  <!-- Mirrors -->
  <mirrors>
    <mirror>
      <id>central-mirror</id>
      <name>Maven Central Mirror</name>
      <url>${MAVEN_CENTRAL}</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>

  <!-- Profiles -->
  <profiles>
    <profile>
      <id>acme-enterprise</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <repositories>
        <repository>
          <id>central</id>
          <name>Maven Central Repository</name>
          <url>${MAVEN_CENTRAL}</url>
          <layout>default</layout>
          <snapshots>
            <enabled>false</enabled>
          </snapshots>
        </repository>
        <repository>
          <id>acme-private</id>
          <name>ACME Private Repository</name>
          <url>${PRIVATE_MAVEN_REGISTRY}</url>
          <layout>default</layout>
          <snapshots>
            <enabled>true</enabled>
            <updatePolicy>daily</updatePolicy>
          </snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>central</id>
          <name>Maven Plugin Repository</name>
          <url>${MAVEN_CENTRAL}</url>
          <layout>default</layout>
          <snapshots>
            <enabled>false</enabled>
          </snapshots>
          <releases>
            <updatePolicy>never</updatePolicy>
          </releases>
        </pluginRepository>
      </pluginRepositories>
      <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.test.skip>false</maven.test.skip>
      </properties>
    </profile>
    <profile>
      <id>security-scan</id>
      <build>
        <plugins>
          <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <version>8.4.3</version>
            <configuration>
              <format>ALL</format>
              <outputDirectory>${REGISTRY_CONFIG_DIR}/logs</outputDirectory>
              <suppressionFile>${REGISTRY_CONFIG_DIR}/maven/dependency-check-suppressions.xml</suppressionFile>
            </configuration>
          </plugin>
        </plugins>
      </build>
    </profile>
  </profiles>

  <!-- Active profiles -->
  <activeProfiles>
    <activeProfile>acme-enterprise</activeProfile>
  </activeProfiles>

</settings>
EOF

    # Create dependency check suppressions
    cat > "${REGISTRY_CONFIG_DIR}/maven/dependency-check-suppressions.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
  <!-- Example suppressions -->
  <!--
  <suppress>
    <notes>False positive - internal library</notes>
    <packageUrl regex="true">^pkg:maven/com\.acme/.*@.*$</packageUrl>
    <cve>CVE-2023-12345</cve>
  </suppress>
  -->
</suppressions>
EOF

    # Create Maven wrapper properties
    cat > "${REGISTRY_CONFIG_DIR}/maven/maven-wrapper.properties" << EOF
# Maven Wrapper Properties for ACME Enterprise
# Generated on $(date)

distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.5/apache-maven-3.9.5-bin.zip
wrapperUrl=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.2.0/maven-wrapper-3.2.0.jar
EOF

    log_success "Maven registry configuration completed"
}

# Configure NuGet registry
setup_nuget_registry() {
    log_header "Configuring NuGet Registry"
    
    local nuget_config="${REGISTRY_CONFIG_DIR}/nuget/NuGet.Config"
    
    # Create NuGet configuration
    cat > "$nuget_config" << EOF
<?xml version="1.0" encoding="utf-8"?>
<!-- NuGet Configuration for ACME Enterprise -->
<!-- Generated on $(date) -->
<configuration>
  <config>
    <add key="globalPackagesFolder" value="${REGISTRY_CONFIG_DIR}/nuget/.nuget/packages" />
    <add key="repositoryPath" value="${REGISTRY_CONFIG_DIR}/nuget/packages" />
    <add key="defaultPushSource" value="${PRIVATE_NUGET_REGISTRY}" />
    <add key="signatureValidationMode" value="require" />
    <add key="trustedSigners" value="author,repository" />
  </config>

  <packageSources>
    <clear />
    <add key="nuget.org" value="${NUGET_REGISTRY}" protocolVersion="3" />
    <add key="acme-private" value="${PRIVATE_NUGET_REGISTRY}" protocolVersion="3" />
  </packageSources>

  <packageSourceCredentials>
    <acme-private>
      <add key="Username" value="%ACME_NUGET_USERNAME%" />
      <add key="ClearTextPassword" value="%ACME_NUGET_PASSWORD%" />
    </acme-private>
  </packageSourceCredentials>

  <trustedSigners>
    <author name="Microsoft">
      <certificate fingerprint="3F9001EA83C560D712C24CF213C3D312CB3BFF51EE89435D3430BD06B5D0EECE" hashAlgorithm="SHA256" allowUntrustedRoot="false" />
    </author>
    <repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json">
      <certificate fingerprint="0E5F38F57DC1BCC806D8494F4F90FBCEDD988B46760709CBEEC6F4219AA6157D" hashAlgorithm="SHA256" allowUntrustedRoot="false" />
    </repository>
  </trustedSigners>

  <packageManagement>
    <add key="format" value="1" />
    <add key="disabled" value="false" />
  </packageManagement>

  <disabledPackageSources>
    <!-- Disabled sources -->
  </disabledPackageSources>

</configuration>
EOF

    # Create packages.config template
    cat > "${REGISTRY_CONFIG_DIR}/nuget/packages-template.config" << EOF
<?xml version="1.0" encoding="utf-8"?>
<!-- NuGet Packages Configuration Template -->
<packages>
  <!-- Core .NET packages -->
  <package id="Microsoft.Extensions.DependencyInjection" version="7.0.0" targetFramework="net6.0" />
  <package id="Microsoft.Extensions.Configuration" version="7.0.0" targetFramework="net6.0" />
  <package id="Microsoft.Extensions.Logging" version="7.0.0" targetFramework="net6.0" />
  
  <!-- Entity Framework -->
  <package id="Microsoft.EntityFrameworkCore" version="7.0.13" targetFramework="net6.0" />
  <package id="Microsoft.EntityFrameworkCore.SqlServer" version="7.0.13" targetFramework="net6.0" />
  
  <!-- JSON processing -->
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net6.0" />
  <package id="System.Text.Json" version="7.0.3" targetFramework="net6.0" />
  
  <!-- Security -->
  <package id="Microsoft.AspNetCore.Authentication.JwtBearer" version="6.0.24" targetFramework="net6.0" />
  <package id="BCrypt.Net-Next" version="4.0.3" targetFramework="net6.0" />
  
  <!-- Testing -->
  <package id="Microsoft.NET.Test.Sdk" version="17.8.0" targetFramework="net6.0" />
  <package id="xunit" version="2.4.2" targetFramework="net6.0" />
  <package id="xunit.runner.visualstudio" version="2.4.5" targetFramework="net6.0" />
  
  <!-- Internal packages (examples) -->
  <!-- <package id="Acme.Internal.Auth" version="1.2.3" targetFramework="net6.0" /> -->
  <!-- <package id="Acme.Payment.Gateway" version="2.1.0" targetFramework="net6.0" /> -->
</packages>
EOF

    # Create security scanning configuration
    cat > "${REGISTRY_CONFIG_DIR}/nuget/security-scan.json" << EOF
{
  "version": "1.0",
  "tools": {
    "dotnet-audit": {
      "enabled": true,
      "severity": "moderate",
      "output": "${REGISTRY_CONFIG_DIR}/logs/nuget-audit.json"
    },
    "snyk": {
      "enabled": false,
      "token": "%SNYK_TOKEN%",
      "severity": "high"
    }
  },
  "ignore": [],
  "allowedLicenses": [
    "MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-3.0"
  ]
}
EOF

    log_success "NuGet registry configuration completed"
}

# Configure RubyGems registry
setup_rubygems_registry() {
    log_header "Configuring RubyGems Registry"
    
    local gem_config="${REGISTRY_CONFIG_DIR}/rubygems/.gemrc"
    
    # Create gem configuration
    cat > "$gem_config" << EOF
# RubyGems Configuration for ACME Enterprise
# Generated on $(date)

# Sources
:sources:
  - ${RUBYGEMS_REGISTRY}
  - ${PRIVATE_RUBYGEMS_REGISTRY}

# Installation settings
:update_sources: true
:verbose: true
:bulk_threshold: 1000
:backtrace: false
:benchmark: false

# Security settings
:ssl_verify_mode: 1
:ssl_ca_cert: ${REGISTRY_CONFIG_DIR}/certificates/ca-bundle.crt

# Cache settings
:gem: --no-document --user-install
:gemhome: ${REGISTRY_CONFIG_DIR}/rubygems/.gem
:gempath:
  - ${REGISTRY_CONFIG_DIR}/rubygems/.gem
  - /usr/local/lib/ruby/gems

# Install options
install: --no-rdoc --no-ri --env-shebang
update: --no-rdoc --no-ri --env-shebang

# Build options
build: --verbose

# Push settings
:rubygems_api_key: %RUBYGEMS_API_KEY%
EOF

    # Create Gemfile template
    cat > "${REGISTRY_CONFIG_DIR}/rubygems/Gemfile-template" << EOF
# Gemfile Template for ACME Enterprise
# Generated on $(date)

source '${RUBYGEMS_REGISTRY}'
source '${PRIVATE_RUBYGEMS_REGISTRY}' do
  # Internal gems
  # gem 'acme-auth-gem', '~> 1.2'
  # gem 'acme-payment-gem', '~> 2.1'
end

ruby '3.2.0'

# Web framework
gem 'rails', '~> 7.1.0'
gem 'puma', '~> 6.4'

# Database
gem 'pg', '~> 1.5'
gem 'redis', '~> 5.0'

# Authentication & Authorization
gem 'devise', '~> 4.9'
gem 'omniauth', '~> 2.1'
gem 'jwt', '~> 2.7'

# HTTP clients
gem 'faraday', '~> 2.7'
gem 'httparty', '~> 0.21'

# JSON processing
gem 'oj', '~> 3.16'

# Background jobs
gem 'sidekiq', '~> 7.2'

# File processing
gem 'image_processing', '~> 1.12'
gem 'carrierwave', '~> 3.0'

# Security
gem 'bcrypt', '~> 3.1'
gem 'brakeman', '~> 6.0'

group :development, :test do
  gem 'rspec-rails', '~> 6.1'
  gem 'factory_bot_rails', '~> 6.4'
  gem 'faker', '~> 3.2'
  gem 'pry-rails', '~> 0.3'
  gem 'rubocop', '~> 1.57'
  gem 'rubocop-rails', '~> 2.22'
  gem 'bundler-audit', '~> 0.9'
end

group :development do
  gem 'listen', '~> 3.8'
  gem 'spring', '~> 4.1'
end

group :test do
  gem 'capybara', '~> 3.39'
  gem 'selenium-webdriver', '~> 4.15'
  gem 'webmock', '~> 3.19'
end
EOF

    # Create bundle configuration
    cat > "${REGISTRY_CONFIG_DIR}/rubygems/.bundle/config" << EOF
---
BUNDLE_PATH: "${REGISTRY_CONFIG_DIR}/rubygems/.bundle"
BUNDLE_CACHE_PATH: "${REGISTRY_CONFIG_DIR}/rubygems/.bundle/cache"
BUNDLE_DISABLE_SHARED_GEMS: "true"
BUNDLE_JOBS: "4"
BUNDLE_RETRY: "3"
BUNDLE_TIMEOUT: "30"
BUNDLE_USER_CONFIG: "${REGISTRY_CONFIG_DIR}/rubygems/.bundle/config"
BUNDLE_USER_CACHE: "${REGISTRY_CONFIG_DIR}/rubygems/.bundle/cache"
BUNDLE_USER_PLUGIN: "${REGISTRY_CONFIG_DIR}/rubygems/.bundle/plugin"
EOF

    # Create security audit configuration
    cat > "${REGISTRY_CONFIG_DIR}/rubygems/audit-config.yml" << EOF
# RubyGems Security Audit Configuration
# Generated on $(date)

# Bundler Audit settings
bundler_audit:
  update: true
  ignore:
    # Add CVE numbers to ignore
    # - CVE-2023-12345
  
# Ruby Advisory Database
ruby_advisory_db:
  update_interval: daily
  path: ${REGISTRY_CONFIG_DIR}/rubygems/.ruby-advisory-db

# Reporting
report:
  format: json
  output: ${REGISTRY_CONFIG_DIR}/logs/rubygems-audit.json
  verbose: true

# Severity levels
severity:
  minimum: medium
  fail_on: high
EOF

    log_success "RubyGems registry configuration completed"
}

# Configure Go modules
setup_go_registry() {
    log_header "Configuring Go Modules Registry"
    
    # Create Go environment configuration
    cat > "${REGISTRY_CONFIG_DIR}/go/go-env.sh" << EOF
#!/bin/bash
# Go Environment Configuration for ACME Enterprise
# Generated on $(date)

# Go proxy settings
export GOPROXY="${GO_PROXY},direct"
export GOSUMDB="sum.golang.org"
export GONOPROXY="github.com/acme/*,*.acme.com/*"
export GONOSUMDB="github.com/acme/*,*.acme.com/*"
export GOPRIVATE="github.com/acme/*,*.acme.com/*"

# Go module settings
export GO111MODULE="on"
export GOMODCACHE="${REGISTRY_CONFIG_DIR}/go/.gomodcache"
export GOCACHE="${REGISTRY_CONFIG_DIR}/go/.gocache"

# Build settings
export CGO_ENABLED="1"
export GOARCH="amd64"
export GOOS="$(go env GOOS)"

# Security settings
export GOINSECURE=""
export GOTOOLCHAIN="auto"

# Private registry authentication
# export GOPRIVATE_TOKEN="your-private-token"
# git config --global url."https://\${GOPRIVATE_TOKEN}@github.com/acme/".insteadOf "https://github.com/acme/"

echo "Go environment configured for ACME Enterprise"
echo "GOPROXY: \$GOPROXY"
echo "GOPRIVATE: \$GOPRIVATE"
echo "GOMODCACHE: \$GOMODCACHE"
EOF

    chmod +x "${REGISTRY_CONFIG_DIR}/go/go-env.sh"

    # Create go.mod template
    cat > "${REGISTRY_CONFIG_DIR}/go/go-mod-template" << EOF
module github.com/acme/test-service

go 1.21

require (
	// Web frameworks
	github.com/gin-gonic/gin v1.9.1
	github.com/labstack/echo/v4 v4.11.3
	github.com/gorilla/mux v1.8.1

	// Database
	gorm.io/gorm v1.25.5
	gorm.io/driver/postgres v1.5.4
	github.com/go-redis/redis/v8 v8.11.5

	// HTTP clients
	github.com/go-resty/resty/v2 v2.10.0

	// Utilities
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.17.0
	github.com/sirupsen/logrus v1.9.3

	// Security
	github.com/golang-jwt/jwt/v5 v5.2.0
	golang.org/x/crypto v0.16.0

	// Testing
	github.com/stretchr/testify v1.8.4
	github.com/golang/mock v1.6.0

	// Internal packages (examples)
	// github.com/acme/auth-service v1.2.3
	// github.com/acme/payment-gateway v2.1.0
)

require (
	// Indirect dependencies will be listed here
)
EOF

    # Create Go security configuration
    cat > "${REGISTRY_CONFIG_DIR}/go/security-config.json" << EOF
{
  "version": "1.0",
  "tools": {
    "govulncheck": {
      "enabled": true,
      "mode": "source",
      "output": "${REGISTRY_CONFIG_DIR}/logs/go-vulncheck.json"
    },
    "gosec": {
      "enabled": true,
      "severity": "medium",
      "confidence": "medium",
      "output": "${REGISTRY_CONFIG_DIR}/logs/gosec.json"
    },
    "nancy": {
      "enabled": false,
      "output": "${REGISTRY_CONFIG_DIR}/logs/nancy.json"
    }
  },
  "ignore": {
    "vulnerabilities": [],
    "packages": []
  },
  "private_modules": [
    "github.com/acme/*",
    "*.acme.com/*"
  ]
}
EOF

    log_success "Go modules registry configuration completed"
}

# Setup private registries (Docker-based)
setup_private_registries() {
    log_header "Setting Up Private Registries"
    
    if ! command_exists docker; then
        log_warning "Docker not available - skipping private registry setup"
        return 0
    fi
    
    # Create docker-compose file for private registries
    cat > "${REGISTRY_CONFIG_DIR}/private-registries/docker-compose.yml" << EOF
version: '3.8'

# Private Package Registries for ACME Enterprise
# Generated on $(date)

services:
  # Verdaccio (NPM private registry)
  verdaccio:
    image: verdaccio/verdaccio:5
    container_name: acme-npm-registry
    ports:
      - "4873:4873"
    volumes:
      - ./verdaccio/config.yaml:/verdaccio/conf/config.yaml
      - verdaccio-storage:/verdaccio/storage
      - verdaccio-plugins:/verdaccio/plugins
    environment:
      - VERDACCIO_USER_NAME=admin
      - VERDACCIO_USER_PWD=admin123
    restart: unless-stopped
    networks:
      - acme-registries

  # PyPI private registry (devpi)
  devpi:
    image: muccg/devpi:latest
    container_name: acme-pypi-registry
    ports:
      - "8080:3141"
    volumes:
      - devpi-data:/data
    environment:
      - DEVPI_PASSWORD=admin123
    restart: unless-stopped
    networks:
      - acme-registries

  # Nexus (Maven, NuGet, etc.)
  nexus:
    image: sonatype/nexus3:latest
    container_name: acme-nexus-registry
    ports:
      - "8081:8081"
      - "5000:5000"  # NuGet
    volumes:
      - nexus-data:/nexus-data
    environment:
      - INSTALL4J_ADD_VM_PARAMS=-Xms1g -Xmx1g -XX:MaxDirectMemorySize=2g
    restart: unless-stopped
    networks:
      - acme-registries

  # RubyGems private registry (Geminabox)
  geminabox:
    image: spoonest/geminabox:latest
    container_name: acme-rubygems-registry
    ports:
      - "9292:9292"
    volumes:
      - geminabox-data:/webapps/geminabox/data
    environment:
      - GEMINABOX_USERNAME=admin
      - GEMINABOX_PASSWORD=admin123
    restart: unless-stopped
    networks:
      - acme-registries

  # Athens (Go modules proxy)
  athens:
    image: gomods/athens:latest
    container_name: acme-go-registry
    ports:
      - "3000:3000"
    volumes:
      - athens-storage:/var/lib/athens
      - ./athens/config.toml:/config/config.toml
    environment:
      - ATHENS_DISK_STORAGE_ROOT=/var/lib/athens
      - ATHENS_STORAGE_TYPE=disk
    restart: unless-stopped
    networks:
      - acme-registries

volumes:
  verdaccio-storage:
  verdaccio-plugins:
  devpi-data:
  nexus-data:
  geminabox-data:
  athens-storage:

networks:
  acme-registries:
    driver: bridge
EOF

    # Create Verdaccio configuration
    mkdir -p "${REGISTRY_CONFIG_DIR}/private-registries/verdaccio"
    cat > "${REGISTRY_CONFIG_DIR}/private-registries/verdaccio/config.yaml" << EOF
# Verdaccio Configuration for ACME Enterprise
# Generated on $(date)

storage: /verdaccio/storage/data
plugins: /verdaccio/plugins

web:
  title: ACME Enterprise NPM Registry
  gravatar: true
  scope: '@acme'
  sort_packages: asc

auth:
  htpasswd:
    file: /verdaccio/storage/htpasswd
    max_users: 1000

uplinks:
  npmjs:
    url: https://registry.npmjs.org/
    cache: true

packages:
  '@acme/*':
    access: \$authenticated
    publish: \$authenticated
    unpublish: \$authenticated
    proxy: npmjs

  '@internal/*':
    access: \$authenticated
    publish: \$authenticated
    unpublish: \$authenticated

  '**':
    access: \$all
    publish: \$authenticated
    unpublish: \$authenticated
    proxy: npmjs

server:
  keepAliveTimeout: 60

middlewares:
  audit:
    enabled: true

logs:
  - { type: stdout, format: pretty, level: http }

security:
  api:
    legacy: true
    jwt:
      sign:
        expiresIn: 60d
        notBefore: 1
      verify:
        someProp: [value]
EOF

    # Create Athens configuration
    mkdir -p "${REGISTRY_CONFIG_DIR}/private-registries/athens"
    cat > "${REGISTRY_CONFIG_DIR}/private-registries/athens/config.toml" << EOF
# Athens Configuration for ACME Enterprise
# Generated on $(date)

# Storage
StorageType = "disk"

# Network
Port = ":3000"
GoBinary = "go"
GoBinaryEnvVars = ["GOPROXY=direct"]

# Proxy settings
GlobalEndpoint = "https://proxy.golang.org"
GlobalEndpointFallback = true

# Private modules
NoSumPatterns = ["github.com/acme/*", "*.acme.com/*"]
PrivatePatterns = ["github.com/acme/*", "*.acme.com/*"]

# Cache
CloudRuntime = "none"
TimeoutConf = "300s"

# Logging
LogLevel = "info"
LogFormat = "plain"

# Security
ChecksumDB = "https://sum.golang.org"
PathPrefix = ""
BasicAuthUser = ""
BasicAuthPass = ""
EOF

    # Create startup script for private registries
    cat > "${REGISTRY_CONFIG_DIR}/private-registries/start-registries.sh" << EOF
#!/bin/bash
# Start Private Registries for ACME Enterprise
# Generated on $(date)

set -euo pipefail

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

echo "Starting ACME Enterprise private registries..."

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running"
    exit 1
fi

# Start registries
cd "\$SCRIPT_DIR"
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 30

# Check service health
echo "Checking service health:"
echo "- Verdaccio (NPM): http://localhost:4873"
curl -f http://localhost:4873 >/dev/null 2>&1 && echo "  ✅ Ready" || echo "  ❌ Not ready"

echo "- DevPI (PyPI): http://localhost:8080"
curl -f http://localhost:8080 >/dev/null 2>&1 && echo "  ✅ Ready" || echo "  ❌ Not ready"

echo "- Nexus (Maven/NuGet): http://localhost:8081"
curl -f http://localhost:8081 >/dev/null 2>&1 && echo "  ✅ Ready" || echo "  ❌ Not ready"

echo "- Geminabox (RubyGems): http://localhost:9292"
curl -f http://localhost:9292 >/dev/null 2>&1 && echo "  ✅ Ready" || echo "  ❌ Not ready"

echo "- Athens (Go): http://localhost:3000"
curl -f http://localhost:3000 >/dev/null 2>&1 && echo "  ✅ Ready" || echo "  ❌ Not ready"

echo "\nPrivate registries are starting up. Please wait a few minutes for all services to be fully ready."
echo "Access the web interfaces at the URLs shown above."
EOF

    chmod +x "${REGISTRY_CONFIG_DIR}/private-registries/start-registries.sh"

    log_success "Private registries configuration completed"
}

# Generate SSL certificates for private registries
generate_certificates() {
    log_header "Generating SSL Certificates"
    
    local cert_dir="${REGISTRY_CONFIG_DIR}/certificates"
    
    # Generate CA private key
    openssl genrsa -out "${cert_dir}/ca-key.pem" 4096 2>/dev/null
    
    # Generate CA certificate
    openssl req -new -x509 -days 365 -key "${cert_dir}/ca-key.pem" \
        -sha256 -out "${cert_dir}/ca.pem" -subj "/C=US/ST=CA/L=San Francisco/O=ACME Enterprise/CN=ACME CA" 2>/dev/null
    
    # Generate server private key
    openssl genrsa -out "${cert_dir}/server-key.pem" 4096 2>/dev/null
    
    # Generate server certificate signing request
    openssl req -subj "/C=US/ST=CA/L=San Francisco/O=ACME Enterprise/CN=localhost" \
        -sha256 -new -key "${cert_dir}/server-key.pem" -out "${cert_dir}/server.csr" 2>/dev/null
    
    # Create extensions file
    cat > "${cert_dir}/server-extensions.cnf" << EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    
    # Generate server certificate
    openssl x509 -req -days 365 -in "${cert_dir}/server.csr" \
        -CA "${cert_dir}/ca.pem" -CAkey "${cert_dir}/ca-key.pem" \
        -out "${cert_dir}/server-cert.pem" -extensions v3_req \
        -extfile "${cert_dir}/server-extensions.cnf" -CAcreateserial 2>/dev/null
    
    # Create CA bundle
    cat "${cert_dir}/ca.pem" > "${cert_dir}/ca-bundle.crt"
    
    # Set appropriate permissions
    chmod 600 "${cert_dir}"/*-key.pem
    chmod 644 "${cert_dir}"/*.pem "${cert_dir}"/*.crt
    
    log_success "SSL certificates generated"
}

# Create registry validation script
create_validation_script() {
    log_header "Creating Registry Validation Script"
    
    cat > "${REGISTRY_CONFIG_DIR}/validate-registries.sh" << EOF
#!/bin/bash
# Registry Validation Script for ACME Enterprise
# Generated on $(date)

set -euo pipefail

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\\033[0;32m'
RED='\\033[0;31m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

validate_npm() {
    echo "Validating NPM configuration..."
    
    # Check npm configuration
    if npm config get registry >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ NPM registry configured\${NC}"
    else
        echo -e "\${RED}❌ NPM registry not configured\${NC}"
        return 1
    fi
    
    # Test package installation
    if npm list express >/dev/null 2>&1 || npm install express --dry-run >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ NPM package installation works\${NC}"
    else
        echo -e "\${YELLOW}⚠️  NPM package installation test failed\${NC}"
    fi
}

validate_pypi() {
    echo "Validating PyPI configuration..."
    
    # Check pip configuration
    if pip3 config list >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ PyPI configuration loaded\${NC}"
    else
        echo -e "\${RED}❌ PyPI configuration not loaded\${NC}"
        return 1
    fi
    
    # Test package installation
    if pip3 show requests >/dev/null 2>&1 || pip3 install requests --dry-run >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ PyPI package installation works\${NC}"
    else
        echo -e "\${YELLOW}⚠️  PyPI package installation test failed\${NC}"
    fi
}

validate_maven() {
    echo "Validating Maven configuration..."
    
    # Check Maven settings
    if mvn help:effective-settings >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ Maven settings loaded\${NC}"
    else
        echo -e "\${RED}❌ Maven settings not loaded\${NC}"
        return 1
    fi
    
    # Test dependency resolution
    if mvn dependency:resolve-sources -q >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ Maven dependency resolution works\${NC}"
    else
        echo -e "\${YELLOW}⚠️  Maven dependency resolution test failed\${NC}"
    fi
}

validate_nuget() {
    echo "Validating NuGet configuration..."
    
    if command -v dotnet >/dev/null 2>&1; then
        # Check NuGet sources
        if dotnet nuget list source >/dev/null 2>&1; then
            echo -e "\${GREEN}✅ NuGet sources configured\${NC}"
        else
            echo -e "\${RED}❌ NuGet sources not configured\${NC}"
            return 1
        fi
    else
        echo -e "\${YELLOW}⚠️  .NET SDK not available - skipping NuGet validation\${NC}"
    fi
}

validate_rubygems() {
    echo "Validating RubyGems configuration..."
    
    # Check gem sources
    if gem sources >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ RubyGems sources configured\${NC}"
    else
        echo -e "\${RED}❌ RubyGems sources not configured\${NC}"
        return 1
    fi
    
    # Test gem installation
    if gem list rails >/dev/null 2>&1 || gem install rails --dry-run >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ RubyGems installation works\${NC}"
    else
        echo -e "\${YELLOW}⚠️  RubyGems installation test failed\${NC}"
    fi
}

validate_go() {
    echo "Validating Go modules configuration..."
    
    # Check Go environment
    if go env GOPROXY >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ Go proxy configured\${NC}"
    else
        echo -e "\${RED}❌ Go proxy not configured\${NC}"
        return 1
    fi
    
    # Test module download
    if go list -m github.com/gin-gonic/gin >/dev/null 2>&1; then
        echo -e "\${GREEN}✅ Go module download works\${NC}"
    else
        echo -e "\${YELLOW}⚠️  Go module download test failed\${NC}"
    fi
}

# Main validation
echo "=== Registry Configuration Validation ==="
echo

validation_results=()

validate_npm && validation_results+=("npm:pass") || validation_results+=("npm:fail")
echo

validate_pypi && validation_results+=("pypi:pass") || validation_results+=("pypi:fail")
echo

validate_maven && validation_results+=("maven:pass") || validation_results+=("maven:fail")
echo

validate_nuget && validation_results+=("nuget:pass") || validation_results+=("nuget:fail")
echo

validate_rubygems && validation_results+=("rubygems:pass") || validation_results+=("rubygems:fail")
echo

validate_go && validation_results+=("go:pass") || validation_results+=("go:fail")
echo

# Summary
echo "=== Validation Summary ==="
passed=0
failed=0

for result in "\${validation_results[@]}"; do
    registry=\$(echo "\$result" | cut -d: -f1)
    status=\$(echo "\$result" | cut -d: -f2)
    
    if [ "\$status" = "pass" ]; then
        echo -e "\${GREEN}✅ \$registry\${NC}"
        ((passed++))
    else
        echo -e "\${RED}❌ \$registry\${NC}"
        ((failed++))
    fi
done

echo
echo "Passed: \$passed, Failed: \$failed"

if [ \$failed -eq 0 ]; then
    echo -e "\${GREEN}All registry configurations are valid!\${NC}"
    exit 0
else
    echo -e "\${RED}Some registry configurations failed validation.\${NC}"
    exit 1
fi
EOF

    chmod +x "${REGISTRY_CONFIG_DIR}/validate-registries.sh"
    
    log_success "Registry validation script created"
}

# Create comprehensive documentation
create_documentation() {
    log_header "Creating Documentation"
    
    cat > "${REGISTRY_CONFIG_DIR}/README.md" << EOF
# Multi-Registry Configuration for ACME Enterprise

This directory contains comprehensive configuration files for multiple package registries used in the ACME Enterprise test environment.

## Supported Registries

- **NPM** (Node.js packages)
- **PyPI** (Python packages)
- **Maven** (Java packages)
- **NuGet** (.NET packages)
- **RubyGems** (Ruby packages)
- **Go Modules** (Go packages)

## Directory Structure

\`\`\`
registry-config/
├── npm/                    # NPM configuration
│   ├── .npmrc             # NPM registry settings
│   ├── package-template.json
│   └── audit-config.json
├── pypi/                   # PyPI configuration
│   ├── pip.conf           # Pip configuration
│   ├── requirements-template.txt
│   └── safety-config.json
├── maven/                  # Maven configuration
│   ├── settings.xml       # Maven settings
│   └── dependency-check-suppressions.xml
├── nuget/                  # NuGet configuration
│   ├── NuGet.Config       # NuGet settings
│   └── packages-template.config
├── rubygems/              # RubyGems configuration
│   ├── .gemrc             # Gem configuration
│   ├── Gemfile-template
│   └── .bundle/config
├── go/                     # Go modules configuration
│   ├── go-env.sh          # Go environment setup
│   ├── go-mod-template
│   └── security-config.json
├── private-registries/     # Private registry setup
│   ├── docker-compose.yml
│   └── start-registries.sh
├── certificates/           # SSL certificates
└── logs/                   # Registry logs
\`\`\`

## Quick Start

1. **Setup all registries:**
   \`\`\`bash
   ./setup-registries.sh
   \`\`\`

2. **Validate configuration:**
   \`\`\`bash
   ./validate-registries.sh
   \`\`\`

3. **Start private registries (optional):**
   \`\`\`bash
   ./private-registries/start-registries.sh
   \`\`\`

## Configuration Details

### NPM Configuration
- Primary registry: npmjs.org
- Scoped registries for @acme, @internal, @company
- Security audit enabled
- Cache optimization

### PyPI Configuration
- Primary index: pypi.org
- Additional index for internal packages
- Security scanning with safety
- Trusted hosts configuration

### Maven Configuration
- Central repository: repo1.maven.org
- Private repository support
- OWASP dependency check integration
- Proxy and mirror support

### NuGet Configuration
- Primary source: nuget.org
- Private package source support
- Package signature validation
- Trusted signers configuration

### RubyGems Configuration
- Primary source: rubygems.org
- Private gem server support
- Bundler audit integration
- SSL verification enabled

### Go Modules Configuration
- Proxy: proxy.golang.org
- Private module support
- Checksum database validation
- Module cache optimization

## Security Features

- **Vulnerability Scanning**: Integrated security scanning for all registries
- **SSL/TLS**: Proper certificate validation and custom CA support
- **Authentication**: Token-based authentication for private registries
- **Audit Logging**: Comprehensive audit trails for all package operations
- **Policy Enforcement**: Configurable security policies and compliance checks

## Environment Variables

Set these environment variables for full functionality:

\`\`\`bash
# NPM
export NPM_TOKEN="your-npm-token"
export PRIVATE_NPM_TOKEN="your-private-npm-token"

# PyPI
export PYPI_USERNAME="your-pypi-username"
export PYPI_PASSWORD="your-pypi-password"

# Maven
export MAVEN_CENTRAL_USERNAME="your-maven-username"
export MAVEN_CENTRAL_PASSWORD="your-maven-password"
export ACME_MAVEN_USERNAME="your-acme-maven-username"
export ACME_MAVEN_PASSWORD="your-acme-maven-password"

# NuGet
export ACME_NUGET_USERNAME="your-nuget-username"
export ACME_NUGET_PASSWORD="your-nuget-password"

# RubyGems
export RUBYGEMS_API_KEY="your-rubygems-api-key"

# Go
export GOPRIVATE_TOKEN="your-go-private-token"
\`\`\`

## Troubleshooting

### Common Issues

1. **Certificate Errors**
   - Ensure CA certificates are properly installed
   - Check SSL/TLS configuration
   - Verify certificate paths

2. **Authentication Failures**
   - Verify API tokens and credentials
   - Check token expiration
   - Ensure proper scoping

3. **Network Issues**
   - Check proxy configuration
   - Verify firewall rules
   - Test connectivity to registries

4. **Permission Errors**
   - Check file permissions
   - Verify user access rights
   - Ensure proper directory ownership

### Debug Commands

\`\`\`bash
# NPM debug
npm config list
npm doctor

# PyPI debug
pip3 config debug
pip3 list --outdated

# Maven debug
mvn help:effective-settings
mvn dependency:tree

# NuGet debug
dotnet nuget list source
dotnet restore --verbosity detailed

# RubyGems debug
gem environment
bundle config

# Go debug
go env
go mod verify
\`\`\`

## Integration with Typosentinel

This registry configuration is designed to work seamlessly with Typosentinel:

1. **Package Scanning**: All registries are configured for comprehensive package scanning
2. **Vulnerability Detection**: Security tools are integrated for each registry
3. **Audit Trails**: Detailed logging for security analysis
4. **Policy Enforcement**: Configurable security policies
5. **Reporting**: Standardized reporting formats

## Maintenance

### Regular Tasks

1. **Update Dependencies**: Regularly update package dependencies
2. **Security Scans**: Run security scans on all registries
3. **Certificate Renewal**: Renew SSL certificates before expiration
4. **Log Rotation**: Manage log files to prevent disk space issues
5. **Backup**: Regular backup of configuration and cache data

### Monitoring

- Monitor registry availability and performance
- Track security scan results
- Monitor certificate expiration
- Track package download statistics
- Monitor private registry health

## Support

For issues or questions:

1. Check the troubleshooting section
2. Review log files in the logs/ directory
3. Run the validation script
4. Contact the ACME Enterprise Security Team

---

*Generated on $(date) for ACME Enterprise Test Environment*
EOF

    log_success "Documentation created"
}

# Main execution
main() {
    log_header "Multi-Registry Environment Setup"
    log_info "Starting registry configuration for ACME Enterprise"
    
    # Initialize log file
    echo "Registry setup started at $(date)" > "$LOG_FILE"
    
    # Check dependencies
    if ! check_dependencies; then
        log_error "Dependency check failed"
        exit 1
    fi
    
    # Setup directory structure
    setup_directories
    
    # Configure each registry
    setup_npm_registry
    setup_pypi_registry
    setup_maven_registry
    setup_nuget_registry
    setup_rubygems_registry
    setup_go_registry
    
    # Setup private registries
    setup_private_registries
    
    # Generate certificates
    generate_certificates
    
    # Create validation script
    create_validation_script
    
    # Create documentation
    create_documentation
    
    log_header "Setup Complete"
    log_success "Multi-registry environment setup completed successfully!"
    log_info "Configuration files created in: $REGISTRY_CONFIG_DIR"
    log_info "Log file: $LOG_FILE"
    log_info "Next steps:"
    log_info "  1. Review configuration files"
    log_info "  2. Set environment variables"
    log_info "  3. Run validation: ./validate-registries.sh"
    log_info "  4. Start private registries (optional): ./private-registries/start-registries.sh"
    
    echo
    echo -e "${GREEN}🎉 Registry configuration setup complete!${NC}"
    echo -e "${BLUE}📁 Configuration directory: ${REGISTRY_CONFIG_DIR}${NC}"
    echo -e "${BLUE}📋 Validation script: ${REGISTRY_CONFIG_DIR}/validate-registries.sh${NC}"
    echo -e "${BLUE}📚 Documentation: ${REGISTRY_CONFIG_DIR}/README.md${NC}"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi