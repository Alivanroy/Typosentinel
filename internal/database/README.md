# Database Schema Design

This document describes the database schema design for TypoSentinel's enterprise repository scanning features.

## Overview

The database schema is designed to support:
- Repository metadata storage
- Organization data management
- Scan results and findings tracking
- Job queue and progress monitoring
- Dependency analysis and vulnerability tracking

## Schema Components

### Core Tables

#### 1. Organizations (`organizations`)
Stores metadata about organizations being scanned.

**Key Fields:**
- `platform`: Source platform (github, gitlab, etc.)
- `login`: Organization identifier
- `scan_status`: Current scan status
- `scan_config`: Organization-specific scan configuration
- `metadata`: Platform-specific additional data

#### 2. Repositories (`repositories`)
Stores metadata about individual repositories.

**Key Fields:**
- `platform`: Source platform
- `organization`: Parent organization
- `full_name`: Complete repository identifier
- `scan_status`: Current scan status
- `language`: Primary programming language
- `is_private`, `is_fork`, `is_archived`: Repository flags
- `metadata`: Additional repository data

#### 3. Scan Jobs (`scan_jobs`)
Tracks organization-wide scan jobs and their progress.

**Key Fields:**
- `job_id`: Unique job identifier (UUID)
- `job_type`: Type of scan (organization_scan, etc.)
- `status`: Job status (pending, running, completed, etc.)
- `progress_percentage`: Job completion percentage
- `scan_config`: Job-specific configuration
- `total_repositories`, `completed_repositories`: Progress tracking

#### 4. Scan Results (`scan_results`)
Stores results of individual repository scans.

**Key Fields:**
- `repository_id`: Reference to scanned repository
- `scan_id`: Unique scan session identifier
- `scan_type`: Type of scan performed
- `status`: Scan completion status
- `results`: Detailed scan results (JSONB)
- `sarif_output`: SARIF-formatted output
- `threats_found`, `vulnerabilities_found`: Summary counts

#### 5. Scan Findings (`scan_findings`)
Detailed findings from scans (threats, vulnerabilities, etc.).

**Key Fields:**
- `finding_type`: Type of finding (typosquatting, vulnerability, etc.)
- `severity`: Finding severity level
- `package_name`: Affected package
- `cve_id`: CVE identifier (for vulnerabilities)
- `suspected_target`: Target package (for typosquatting)
- `status`: Finding resolution status

#### 6. Repository Dependencies (`repository_dependencies`)
Tracks package dependencies found in repositories.

**Key Fields:**
- `package_name`: Dependency package name
- `package_ecosystem`: Package ecosystem (npm, pypi, etc.)
- `dependency_type`: Type of dependency (direct, transitive, etc.)
- `manifest_file`: Source manifest file
- `has_vulnerabilities`: Security flag
- `is_malicious`: Malware detection flag

## Migration System

The schema uses a migration-based approach for version control:

### Migration Files
- Located in `migrations/` directory
- Named with format: `001_description.sql`
- Embedded in the binary using Go's `embed` package
- Applied automatically on startup

### Schema Manager
The `SchemaManager` handles:
- Migration discovery and application
- Checksum validation
- Schema validation
- Migration status tracking

## Usage

### Initializing the Database

```go
import (
    "github.com/Alivanroy/Typosentinel/internal/database"
    "github.com/Alivanroy/Typosentinel/pkg/logger"
)

// Create schema manager
schemaManager := database.NewSchemaManager(db, logger)

// Initialize schema and apply migrations
if err := schemaManager.Initialize(ctx); err != nil {
    log.Fatal("Failed to initialize database schema:", err)
}

// Validate schema
if err := schemaManager.ValidateSchema(ctx); err != nil {
    log.Fatal("Schema validation failed:", err)
}
```

### Checking Migration Status

```go
migrations, err := schemaManager.GetMigrationStatus(ctx)
if err != nil {
    log.Fatal("Failed to get migration status:", err)
}

for _, migration := range migrations {
    status := "pending"
    if migration.AppliedAt != nil {
        status = "applied"
    }
    fmt.Printf("Migration %d: %s [%s]\n", migration.Version, migration.Name, status)
}
```

## Database Configuration

### PostgreSQL (Recommended for Production)

```yaml
database:
  type: postgres
  host: localhost
  port: 5432
  database: typosentinel
  username: typosentinel_user
  password: ${DB_PASSWORD}
  ssl_mode: require
  max_open_conns: 25
  max_idle_conns: 10
  conn_max_lifetime: 1h
  migrations_path: internal/database/migrations
```

### SQLite (Development/Testing)

```yaml
database:
  type: sqlite
  database: ./data/typosentinel.db
  migrations_path: internal/database/migrations
```

## Indexes and Performance

### Key Indexes
- **Repository lookups**: `platform`, `organization`, `full_name`
- **Scan tracking**: `scan_status`, `last_scanned_at`
- **Finding queries**: `finding_type`, `severity`, `package_name`
- **Job monitoring**: `status`, `created_at`, `priority`
- **JSONB fields**: GIN indexes for metadata searches

### Query Optimization
- Composite indexes for common query patterns
- Partial indexes for active/problematic records
- JSONB indexes for flexible metadata queries

## Security Considerations

### Data Protection
- Sensitive configuration stored in JSONB fields
- No plain-text secrets in database
- Audit trail through timestamps

### Access Control
- Database-level user permissions
- Connection pooling and limits
- SSL/TLS encryption for connections

## Monitoring and Maintenance

### Health Checks
- Table existence validation
- Migration status monitoring
- Connection pool metrics

### Cleanup Procedures
- Old scan results archival
- Completed job cleanup
- Dependency data refresh

## Future Enhancements

### Planned Features
- Audit logging table
- User management and permissions
- Scan scheduling and triggers
- Historical trend analysis
- Cross-repository dependency graphs

### Scalability Considerations
- Table partitioning for large datasets
- Read replicas for reporting
- Archival strategies for historical data
- Caching layers for frequent queries