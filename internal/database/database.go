package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// Database represents the database connection and operations
type Database struct {
	db *sql.DB
}

// Config holds database configuration
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// New creates a new database connection
func New(config Config) (*Database, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &Database{db: db}, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// GetDB returns the underlying sql.DB connection
func (d *Database) GetDB() *sql.DB {
	return d.db
}

// Migrate runs database migrations
func (d *Database) Migrate() error {
	migrations := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
		
		`CREATE TABLE IF NOT EXISTS organizations (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) NOT NULL,
			description TEXT,
			settings JSONB DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			full_name VARCHAR(255),
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			organization_id UUID REFERENCES organizations(id),
			is_active BOOLEAN DEFAULT true,
			last_login TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS api_keys (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			key_hash VARCHAR(255) UNIQUE NOT NULL,
			name VARCHAR(255) NOT NULL,
			user_id UUID REFERENCES users(id),
			organization_id UUID REFERENCES organizations(id),
			permissions JSONB DEFAULT '[]',
			is_active BOOLEAN DEFAULT true,
			expires_at TIMESTAMP WITH TIME ZONE,
			last_used TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS scan_requests (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID REFERENCES users(id),
			organization_id UUID REFERENCES organizations(id),
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			options JSONB DEFAULT '{}',
			started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			completed_at TIMESTAMP WITH TIME ZONE,
			error_message TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS scan_results (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			scan_request_id UUID REFERENCES scan_requests(id),
			package_name VARCHAR(255) NOT NULL,
			package_version VARCHAR(100),
			registry VARCHAR(50) NOT NULL,
			threats_found INTEGER DEFAULT 0,
			warnings_found INTEGER DEFAULT 0,
			severity VARCHAR(20),
			result_data JSONB DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS threats (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			scan_result_id UUID REFERENCES scan_results(id),
			package_name VARCHAR(255) NOT NULL,
			package_version VARCHAR(100),
			registry VARCHAR(50) NOT NULL,
			threat_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			confidence DECIMAL(3,2),
			description TEXT,
			similar_to VARCHAR(255),
			recommendation TEXT,
			detection_method VARCHAR(100),
			evidence JSONB DEFAULT '[]',
			detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS policies (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			organization_id UUID REFERENCES organizations(id),
			name VARCHAR(255) NOT NULL,
			description TEXT,
			rules JSONB DEFAULT '[]',
			is_active BOOLEAN DEFAULT true,
			created_by UUID REFERENCES users(id),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID REFERENCES users(id),
			organization_id UUID REFERENCES organizations(id),
			action VARCHAR(100) NOT NULL,
			resource_type VARCHAR(50),
			resource_id UUID,
			details JSONB DEFAULT '{}',
			ip_address INET,
			user_agent TEXT,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`,
		
		`CREATE TABLE IF NOT EXISTS package_metadata (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			name VARCHAR(255) NOT NULL,
			registry VARCHAR(50) NOT NULL,
			version VARCHAR(100),
			description TEXT,
			author VARCHAR(255),
			license VARCHAR(100),
			homepage VARCHAR(500),
			repository VARCHAR(500),
			downloads BIGINT DEFAULT 0,
			size BIGINT DEFAULT 0,
			dependencies JSONB DEFAULT '[]',
			keywords JSONB DEFAULT '[]',
			creation_date TIMESTAMP WITH TIME ZONE,
			last_updated TIMESTAMP WITH TIME ZONE,
			metadata JSONB DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			UNIQUE(name, registry, version)
		);`,
		
		// Indexes for better performance
		`CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id);`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_organization_id ON api_keys(organization_id);`,
		`CREATE INDEX IF NOT EXISTS idx_scan_requests_user_id ON scan_requests(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_scan_requests_organization_id ON scan_requests(organization_id);`,
		`CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status);`,
		`CREATE INDEX IF NOT EXISTS idx_scan_results_scan_request_id ON scan_results(scan_request_id);`,
		`CREATE INDEX IF NOT EXISTS idx_scan_results_package_name ON scan_results(package_name);`,
		`CREATE INDEX IF NOT EXISTS idx_threats_scan_result_id ON threats(scan_result_id);`,
		`CREATE INDEX IF NOT EXISTS idx_threats_package_name ON threats(package_name);`,
		`CREATE INDEX IF NOT EXISTS idx_threats_threat_type ON threats(threat_type);`,
		`CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_policies_organization_id ON policies(organization_id);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_organization_id ON audit_logs(organization_id);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);`,
		`CREATE INDEX IF NOT EXISTS idx_package_metadata_name_registry ON package_metadata(name, registry);`,
		`CREATE INDEX IF NOT EXISTS idx_package_metadata_registry ON package_metadata(registry);`,
	}

	for _, migration := range migrations {
		if _, err := d.db.Exec(migration); err != nil {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	return nil
}

// SaveScanRequest saves a scan request to the database
func (d *Database) SaveScanRequest(ctx context.Context, request *types.ScanRequest) error {
	query := `
		INSERT INTO scan_requests (id, user_id, organization_id, status, options)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := d.db.ExecContext(ctx, query,
		request.ID, request.UserID, request.OrganizationID,
		request.Status, request.Options)
	return err
}

// UpdateScanRequest updates a scan request status
func (d *Database) UpdateScanRequest(ctx context.Context, id uuid.UUID, status types.ScanStatus, errorMsg string) error {
	query := `
		UPDATE scan_requests 
		SET status = $2, error_message = $3, completed_at = CASE WHEN $2 IN ('completed', 'failed') THEN NOW() ELSE completed_at END
		WHERE id = $1
	`
	_, err := d.db.ExecContext(ctx, query, id, status, errorMsg)
	return err
}

// GetScanRequest retrieves a scan request by ID
func (d *Database) GetScanRequest(ctx context.Context, id uuid.UUID) (*types.ScanRequest, error) {
	query := `
		SELECT id, user_id, organization_id, status, options, started_at, completed_at, error_message, created_at
		FROM scan_requests
		WHERE id = $1
	`
	row := d.db.QueryRowContext(ctx, query, id)

	request := &types.ScanRequest{}
	err := row.Scan(
		&request.ID, &request.UserID, &request.OrganizationID,
		&request.Status, &request.Options, &request.StartedAt,
		&request.CompletedAt, &request.ErrorMessage, &request.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return request, nil
}

// SaveScanResult saves a scan result to the database
func (d *Database) SaveScanResult(ctx context.Context, result *types.ScanResponse) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Save scan result
	resultQuery := `
		INSERT INTO scan_results (id, scan_request_id, package_name, package_version, registry, threats_found, warnings_found, severity, result_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err = tx.ExecContext(ctx, resultQuery,
		result.ID, result.ScanID, result.PackageName, result.PackageVersion,
		result.Registry, len(result.Threats), len(result.Warnings),
		result.Summary.HighestSeverity, result)
	if err != nil {
		return err
	}

	// Save threats
	for _, threat := range result.Threats {
		threatQuery := `
			INSERT INTO threats (id, scan_result_id, package_name, package_version, registry, threat_type, severity, confidence, description, similar_to, recommendation, detection_method, evidence)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		`
		_, err = tx.ExecContext(ctx, threatQuery,
			threat.ID, result.ID, threat.Package, threat.Version,
			threat.Registry, threat.Type, threat.Severity, threat.Confidence,
			threat.Description, threat.SimilarTo, threat.Recommendation,
			threat.DetectionMethod, threat.Evidence)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetScanResults retrieves scan results for a scan request
func (d *Database) GetScanResults(ctx context.Context, scanID uuid.UUID) ([]*types.ScanResponse, error) {
	query := `
		SELECT id, scan_request_id, package_name, package_version, registry, threats_found, warnings_found, severity, result_data, created_at
		FROM scan_results
		WHERE scan_request_id = $1
		ORDER BY created_at
	`
	rows, err := d.db.QueryContext(ctx, query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.ScanResponse
	for rows.Next() {
		result := &types.ScanResponse{}
		err := rows.Scan(
			&result.ID, &result.ScanID, &result.PackageName, &result.PackageVersion,
			&result.Registry, &result.Summary.TotalThreats, &result.Summary.TotalWarnings,
			&result.Summary.HighestSeverity, &result, &result.Timestamp,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

// GetThreats retrieves threats for a scan result
func (d *Database) GetThreats(ctx context.Context, scanResultID uuid.UUID) ([]*types.Threat, error) {
	query := `
		SELECT id, package_name, package_version, registry, threat_type, severity, confidence, description, similar_to, recommendation, detection_method, evidence, detected_at
		FROM threats
		WHERE scan_result_id = $1
		ORDER BY severity DESC, confidence DESC
	`
	rows, err := d.db.QueryContext(ctx, query, scanResultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []*types.Threat
	for rows.Next() {
		threat := &types.Threat{}
		err := rows.Scan(
			&threat.ID, &threat.Package, &threat.Version, &threat.Registry,
			&threat.Type, &threat.Severity, &threat.Confidence, &threat.Description,
			&threat.SimilarTo, &threat.Recommendation, &threat.DetectionMethod,
			&threat.Evidence, &threat.DetectedAt,
		)
		if err != nil {
			return nil, err
		}
		threats = append(threats, threat)
	}

	return threats, nil
}

// SavePackageMetadata saves package metadata to the database
func (d *Database) SavePackageMetadata(ctx context.Context, metadata *types.PackageMetadata) error {
	query := `
		INSERT INTO package_metadata (name, registry, version, description, author, license, homepage, repository, downloads, size, dependencies, keywords, creation_date, last_updated, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (name, registry, version) DO UPDATE SET
			description = EXCLUDED.description,
			author = EXCLUDED.author,
			license = EXCLUDED.license,
			homepage = EXCLUDED.homepage,
			repository = EXCLUDED.repository,
			downloads = EXCLUDED.downloads,
			size = EXCLUDED.size,
			dependencies = EXCLUDED.dependencies,
			keywords = EXCLUDED.keywords,
			last_updated = EXCLUDED.last_updated,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
	`
	_, err := d.db.ExecContext(ctx, query,
		metadata.Name, metadata.Registry, metadata.Version, metadata.Description,
		metadata.Author, metadata.License, metadata.Homepage, metadata.Repository,
		metadata.Downloads, metadata.Size, metadata.Dependencies, metadata.Keywords,
		metadata.CreationDate, metadata.LastUpdated, metadata.Metadata)
	return err
}

// GetPackageMetadata retrieves package metadata from the database
func (d *Database) GetPackageMetadata(ctx context.Context, name, registry, version string) (*types.PackageMetadata, error) {
	query := `
		SELECT name, registry, version, description, author, license, homepage, repository, downloads, size, dependencies, keywords, creation_date, last_updated, metadata, created_at, updated_at
		FROM package_metadata
		WHERE name = $1 AND registry = $2 AND version = $3
	`
	row := d.db.QueryRowContext(ctx, query, name, registry, version)

	metadata := &types.PackageMetadata{}
	err := row.Scan(
		&metadata.Name, &metadata.Registry, &metadata.Version, &metadata.Description,
		&metadata.Author, &metadata.License, &metadata.Homepage, &metadata.Repository,
		&metadata.Downloads, &metadata.Size, &metadata.Dependencies, &metadata.Keywords,
		&metadata.CreationDate, &metadata.LastUpdated, &metadata.Metadata,
		&metadata.CreatedAt, &metadata.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

// SaveAuditLog saves an audit log entry
func (d *Database) SaveAuditLog(ctx context.Context, log *types.AuditLog) error {
	query := `
		INSERT INTO audit_logs (user_id, organization_id, action, resource_type, resource_id, details, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := d.db.ExecContext(ctx, query,
		log.UserID, log.OrganizationID, log.Action, log.ResourceType,
		log.ResourceID, log.Details, log.IPAddress, log.UserAgent)
	return err
}

// GetUserScans retrieves scan requests for a user
func (d *Database) GetUserScans(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*types.ScanRequest, error) {
	query := `
		SELECT id, user_id, organization_id, status, options, started_at, completed_at, error_message, created_at
		FROM scan_requests
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := d.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*types.ScanRequest
	for rows.Next() {
		scan := &types.ScanRequest{}
		err := rows.Scan(
			&scan.ID, &scan.UserID, &scan.OrganizationID,
			&scan.Status, &scan.Options, &scan.StartedAt,
			&scan.CompletedAt, &scan.ErrorMessage, &scan.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}

	return scans, nil
}

// GetThreatStatistics retrieves threat statistics
func (d *Database) GetThreatStatistics(ctx context.Context, organizationID *uuid.UUID, days int) (map[string]interface{}, error) {
	baseQuery := `
		SELECT 
			threat_type,
			severity,
			COUNT(*) as count,
			DATE_TRUNC('day', detected_at) as date
		FROM threats t
		JOIN scan_results sr ON t.scan_result_id = sr.id
		JOIN scan_requests sreq ON sr.scan_request_id = sreq.id
		WHERE t.detected_at >= NOW() - INTERVAL '%d days'
	`

	args := []interface{}{}
	argIndex := 1

	if organizationID != nil {
		baseQuery += fmt.Sprintf(" AND sreq.organization_id = $%d", argIndex)
		args = append(args, *organizationID)
		argIndex++
	}

	baseQuery += " GROUP BY threat_type, severity, DATE_TRUNC('day', detected_at) ORDER BY date DESC"

	query := fmt.Sprintf(baseQuery, days)
	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]interface{})
	threatsByType := make(map[string]int)
	threatsBySeverity := make(map[string]int)
	threatsByDate := make(map[string]int)

	for rows.Next() {
		var threatType, severity, date string
		var count int
		err := rows.Scan(&threatType, &severity, &count, &date)
		if err != nil {
			return nil, err
		}

		threatsByType[threatType] += count
		threatsBySeverity[severity] += count
		threatsByDate[date] += count
	}

	stats["by_type"] = threatsByType
	stats["by_severity"] = threatsBySeverity
	stats["by_date"] = threatsByDate

	return stats, nil
}