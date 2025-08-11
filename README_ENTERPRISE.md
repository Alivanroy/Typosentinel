# Typosentinel Enterprise Features

This document describes the enterprise features implemented for Typosentinel, including SPDX and CycloneDX format generators, enhanced remediation engine, multi-tenant architecture, and ML-based threat prediction.

## Features Overview

### 1. Output Format Generators

#### SPDX Format Generator
- **Location**: `internal/enterprise/formats/spdx.go`
- **Purpose**: Generates Software Package Data Exchange (SPDX) format reports
- **Features**:
  - SPDX 2.3 specification compliance
  - Package and file information
  - License detection and reporting
  - Vulnerability mapping
  - Relationship tracking

#### CycloneDX Format Generator
- **Location**: `internal/enterprise/formats/cyclonedx.go`
- **Purpose**: Generates CycloneDX Software Bill of Materials (SBOM)
- **Features**:
  - CycloneDX 1.5 specification compliance
  - Component dependency tracking
  - Vulnerability annotations
  - Service and metadata inclusion
  - JSON and XML output support

### 2. Enhanced Remediation Engine

#### Core Components
- **Enhanced Engine**: `internal/enterprise/remediation/enhanced_engine.go`
- **Dependency Updater**: `internal/enterprise/remediation/dependency_updater.go`
- **Pull Request Generator**: `internal/enterprise/remediation/pr_generator.go`

#### Features
- **Automated Dependency Updates**: Automatically updates vulnerable dependencies
- **Pull Request Generation**: Creates PRs with remediation changes
- **Multi-language Support**: Supports npm, pip, go mod, maven, gradle
- **Risk Assessment**: Evaluates remediation impact before applying
- **Rollback Capabilities**: Provides rollback mechanisms for failed remediations

### 3. Multi-Tenant Architecture

#### Components
- **Tenant Manager**: `internal/enterprise/multitenant/tenant_manager.go`
- **Types and Models**: `internal/enterprise/multitenant/types.go`

#### Features
- **Tenant Isolation**: Complete data and resource isolation
- **Quota Management**: Configurable limits per tenant
- **Security Settings**: Per-tenant security configurations
- **Usage Tracking**: Detailed usage metrics and billing support
- **API Key Management**: Tenant-specific authentication

### 4. ML-Based Threat Prediction

#### Components
- **Threat Predictor**: `internal/ml/threat_predictor.go`
- **Enhanced ML**: `internal/ml/enhanced.go`
- **Model Management**: `internal/ml/models.go`

#### Features
- **Real-time Prediction**: Predicts threat likelihood and severity
- **Multiple Models**: Logistic regression, random forest, neural networks
- **Ensemble Learning**: Combines multiple models for better accuracy
- **Continuous Learning**: Updates models with new threat data
- **Risk Scoring**: Provides detailed risk assessments

### 5. Enterprise Integration Layer

#### Components
- **Integration Layer**: `internal/enterprise/integration_layer.go`
- **API Layer**: `internal/enterprise/api_layer.go`

#### Features
- **Unified API**: Single interface for all enterprise features
- **Configuration Management**: Centralized enterprise configuration
- **Metrics Collection**: Comprehensive performance metrics
- **Callback Support**: Webhook notifications for scan completion
- **Priority Queuing**: Scan prioritization based on business needs

## Installation and Setup

### Prerequisites

```bash
# Install Go 1.19 or later
go version

# Install required dependencies
go mod download
```

### Configuration

1. **Enterprise Configuration**:
```yaml
# config/enterprise.yaml
enterprise:
  enabled: true
  multi_tenant_enabled: true
  ml_prediction_enabled: true
  auto_remediation_enabled: true
  pr_generation_enabled: true
  
  # Database configuration for multi-tenancy
  database:
    host: "localhost"
    port: 5432
    name: "typosentinel_enterprise"
    user: "postgres"
    password: "${POSTGRES_PASSWORD}"  # Set via environment variable
    
  # ML configuration
  ml:
    model_path: "./models"
    training_data_path: "./training_data"
    ensemble_enabled: true
    
  # API configuration
  api:
    port: 8080
    host: "0.0.0.0"
    tls_enabled: false
    cors_enabled: true
    authentication_enabled: true
```

2. **Multi-Tenant Setup**:
```bash
# Initialize database
psql -U postgres -c "CREATE DATABASE typosentinel_enterprise;"

# Run migrations (if available)
# go run cmd/migrate/main.go
```

### Building

```bash
# Build the enterprise version
go build -tags enterprise -o typosentinel-enterprise ./cmd/typosentinel

# Or build with all features
go build -ldflags "-X main.enterpriseEnabled=true" -o typosentinel ./cmd/typosentinel
```

## Usage Examples

### 1. Basic Enterprise Scan

```bash
# Scan with SPDX output
./typosentinel-enterprise scan --repo https://github.com/example/repo \
  --output-format spdx \
  --ml-prediction \
  --auto-remediation

# Scan with CycloneDX output
./typosentinel-enterprise scan --repo https://github.com/example/repo \
  --output-format cyclonedx \
  --tenant-id tenant-123
```

### 2. API Usage

#### Start the API Server
```bash
./typosentinel-enterprise server --config config/enterprise.yaml
```

#### Create a Tenant
```bash
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "name": "Acme Corp",
    "description": "Enterprise tenant for Acme Corporation",
    "plan": "enterprise",
    "quotas": {
      "max_scans_per_day": 1000,
      "max_users": 50,
      "max_storage_gb": 100
    }
  }'
```

#### Execute a Scan
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "tenant_id": "tenant-123",
    "repository_url": "https://github.com/example/repo",
    "scan_type": "full",
    "ml_prediction_enabled": true,
    "auto_remediation_enabled": true,
    "pr_generation_enabled": true,
    "output_formats": ["spdx", "cyclonedx", "sarif"],
    "priority": "high"
  }'
```

#### Get ML Prediction
```bash
curl -X POST http://localhost:8080/api/v1/ml/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "package_name": "suspicious-package",
    "version": "1.0.0",
    "description": "A potentially malicious package",
    "author": "unknown@example.com"
  }'
```

### 3. Programmatic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/Alivanroy/Typosentinel/internal/enterprise"
    "github.com/Alivanroy/Typosentinel/internal/enterprise/multitenant"
)

func main() {
    // Initialize enterprise integration layer
    config := &enterprise.EnterpriseConfig{
        MultiTenantEnabled:     true,
        MLPredictionEnabled:    true,
        AutoRemediationEnabled: true,
        PRGenerationEnabled:    true,
    }
    
    integrationLayer, err := enterprise.NewEnterpriseIntegrationLayer(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create a tenant
    tenantReq := &multitenant.CreateTenantRequest{
        Name:        "Example Corp",
        Description: "Example corporation tenant",
        Plan:        "enterprise",
    }
    
    tenant, err := integrationLayer.CreateTenant(context.Background(), tenantReq)
    if err != nil {
        log.Fatal(err)
    }
    
    // Execute an enterprise scan
    scanReq := &enterprise.EnterpriseScanRequest{
        TenantID:               tenant.ID,
        RepositoryURL:          "https://github.com/example/repo",
        ScanType:               enterprise.ScanTypeFull,
        MLPredictionEnabled:    true,
        AutoRemediationEnabled: true,
        PRGenerationEnabled:    true,
        OutputFormats:          []enterprise.OutputFormat{
            enterprise.OutputFormatSPDX,
            enterprise.OutputFormatCycloneDX,
        },
        Priority: enterprise.ScanPriorityHigh,
    }
    
    result, err := integrationLayer.ExecuteEnterpriseScan(context.Background(), scanReq)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Scan completed: %+v\n", result)
}
```

## Output Formats

### SPDX Format
```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "Typosentinel Scan Report",
  "documentNamespace": "https://typosentinel.com/spdx/...",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-example",
      "name": "example-package",
      "downloadLocation": "https://registry.npmjs.org/example-package/-/example-package-1.0.0.tgz",
      "filesAnalyzed": true,
      "licenseConcluded": "MIT",
      "copyrightText": "Copyright 2023 Example Corp"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "summary": "Critical vulnerability in example-package",
      "severity": "CRITICAL"
    }
  ]
}
```

### CycloneDX Format
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2023-12-07T10:00:00Z",
    "tools": [
      {
        "vendor": "Typosentinel",
        "name": "typosentinel-enterprise",
        "version": "1.0.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/example-package@1.0.0",
      "name": "example-package",
      "version": "1.0.0",
      "purl": "pkg:npm/example-package@1.0.0"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/"
      },
      "ratings": [
        {
          "source": {
            "name": "NVD"
          },
          "score": 9.8,
          "severity": "critical",
          "method": "CVSSv3"
        }
      ]
    }
  ]
}
```

## Monitoring and Metrics

### Available Metrics
- **Scan Metrics**: Total scans, success rate, average duration
- **Tenant Metrics**: Active tenants, usage per tenant, quota utilization
- **ML Metrics**: Prediction accuracy, model performance, training metrics
- **Remediation Metrics**: Success rate, time to remediation, rollback frequency

### Health Endpoints
```bash
# Check API health
curl http://localhost:8080/api/v1/health

# Get system status
curl http://localhost:8080/api/v1/status

# Get detailed metrics
curl http://localhost:8080/api/v1/metrics
```

## Security Considerations

### Multi-Tenant Security
- **Data Isolation**: Complete separation of tenant data
- **API Key Management**: Unique keys per tenant
- **Rate Limiting**: Per-tenant rate limits
- **Audit Logging**: Comprehensive audit trails

### ML Security
- **Model Protection**: Encrypted model storage
- **Training Data Privacy**: Anonymized training data
- **Prediction Validation**: Input validation and sanitization

### API Security
- **Authentication**: API key and JWT support
- **Authorization**: Role-based access control
- **TLS Encryption**: HTTPS support
- **Input Validation**: Comprehensive request validation

## Troubleshooting

### Common Issues

1. **Database Connection Issues**:
   ```bash
   # Check database connectivity
   psql -h localhost -U postgres -d typosentinel_enterprise -c "SELECT 1;"
   ```

2. **ML Model Loading Issues**:
   ```bash
   # Check model files
   ls -la ./models/
   
   # Verify model permissions
   chmod 644 ./models/*.json
   ```

3. **API Authentication Issues**:
   ```bash
   # Test API key
   curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/health
   ```

### Logs

```bash
# Enable debug logging
export LOG_LEVEL=debug
./typosentinel-enterprise server

# Check specific component logs
export LOG_COMPONENT=enterprise.multitenant
./typosentinel-enterprise server
```

## Contributing

When contributing to enterprise features:

1. **Follow the existing patterns** in the enterprise modules
2. **Add comprehensive tests** for new functionality
3. **Update documentation** for any API changes
4. **Consider multi-tenant implications** for all new features
5. **Ensure backward compatibility** with existing installations

## License

The enterprise features are subject to the same license as the main Typosentinel project. Please refer to the main LICENSE file for details.