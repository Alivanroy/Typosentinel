package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// OSSService provides a simplified PostgreSQL-based database service for OSS
type OSSService struct {
	db     *sql.DB
	config *config.DatabaseConfig
}

// PackageScan represents a package scan result
type PackageScan struct {
	ID          string                 `json:"id"`
	PackageName string                 `json:"package_name"`
	Registry    string                 `json:"registry"`
	Version     string                 `json:"version,omitempty"`
	Status      string                 `json:"status"` // pending, running, completed, failed
	RiskLevel   string                 `json:"risk_level,omitempty"`
	Threats     []ThreatResult         `json:"threats,omitempty"`
	Summary     string                 `json:"summary,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Duration    int64                  `json:"duration,omitempty"` // seconds
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatResult represents a detected threat
type ThreatResult struct {
	Type               string   `json:"type"`
	Severity           string   `json:"severity"`
	Confidence         float64  `json:"confidence"`
	Description        string   `json:"description"`
	Source             string   `json:"source"`
	AffectedVersions   string   `json:"affected_versions,omitempty"`
	FixedVersion       string   `json:"fixed_version,omitempty"`
	ProposedCorrection string   `json:"proposed_correction,omitempty"`
	CVE                string   `json:"cve,omitempty"`
	References         []string `json:"references,omitempty"`
}

// ScanSummary represents a scan summary for dashboard
type ScanSummary struct {
	ID          string                   `json:"id"`
	PackageName string                   `json:"package_name"`
	Registry    string                   `json:"registry"`
	Status      string                   `json:"status"`
	RiskLevel   string                   `json:"risk_level"`
	ThreatCount int                      `json:"threat_count"`
	Duration    int64                    `json:"duration"`
	StartedAt   time.Time                `json:"started_at"`
	CompletedAt *time.Time               `json:"completed_at"`
	Threats     []map[string]interface{} `json:"threats,omitempty"`
}

// NewOSSService creates a new OSS database service with PostgreSQL or SQLite
func NewOSSService(dbConfig *config.DatabaseConfig) (*OSSService, error) {
	var db *sql.DB
	var err error

	// Debug logging
	log.Printf("[DEBUG] Database config - Type: '%s', Database: '%s'", dbConfig.Type, dbConfig.Database)
	log.Printf("[DEBUG] Database config - Host: '%s', Port: %d, Username: '%s', SSLMode: '%s'", dbConfig.Host, dbConfig.Port, dbConfig.Username, dbConfig.SSLMode)

	// Support both PostgreSQL and SQLite
	if dbConfig.Type == "sqlite" {
		// Open SQLite database
		log.Printf("[DEBUG] Opening SQLite database: %s", dbConfig.Database)
		db, err = sql.Open("sqlite3", dbConfig.Database)
	} else {
		// Open PostgreSQL database
		log.Printf("[DEBUG] Opening PostgreSQL database")
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			dbConfig.Host, dbConfig.Port, dbConfig.Username, dbConfig.Password, dbConfig.Database, dbConfig.SSLMode)
		db, err = sql.Open("postgres", dsn)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	service := &OSSService{
		db:     db,
		config: dbConfig,
	}

	// Initialize schema
	if err := service.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return service, nil
}

// initSchema creates the database tables if they don't exist
func (s *OSSService) initSchema() error {
	var scanTableSQL string

	// Create package_scans table with database-specific syntax
	if s.config.Type == "sqlite" {
		scanTableSQL = `
		CREATE TABLE IF NOT EXISTS package_scans (
			id TEXT PRIMARY KEY,
			package_name TEXT NOT NULL,
			registry TEXT NOT NULL,
			version TEXT,
			status TEXT NOT NULL,
			risk_level TEXT,
			threats TEXT,
			summary TEXT,
			started_at DATETIME NOT NULL,
			completed_at DATETIME,
			duration INTEGER,
			metadata TEXT
		);
		`
	} else {
		scanTableSQL = `
		CREATE TABLE IF NOT EXISTS package_scans (
			id VARCHAR(255) PRIMARY KEY,
			package_name VARCHAR(255) NOT NULL,
			registry VARCHAR(100) NOT NULL,
			version VARCHAR(100),
			status VARCHAR(50) NOT NULL,
			risk_level VARCHAR(50),
			threats JSONB,
			summary TEXT,
			started_at TIMESTAMP WITH TIME ZONE NOT NULL,
			completed_at TIMESTAMP WITH TIME ZONE,
			duration BIGINT,
			metadata JSONB
		);
		`
	}

	// Create indexes
	indexSQL := []string{
		`CREATE INDEX IF NOT EXISTS idx_scans_package ON package_scans(package_name);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_registry ON package_scans(registry);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_status ON package_scans(status);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_started ON package_scans(started_at);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_risk ON package_scans(risk_level);`,
	}

	// Execute schema creation
	if _, err := s.db.Exec(scanTableSQL); err != nil {
		return fmt.Errorf("failed to create package_scans table: %w", err)
	}

	// Create indexes
	for _, sql := range indexSQL {
		if _, err := s.db.Exec(sql); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateScan creates a new package scan record
func (s *OSSService) CreateScan(ctx context.Context, scan *PackageScan) error {
	if scan.ID == "" {
		scan.ID = uuid.New().String()
	}
	if scan.StartedAt.IsZero() {
		scan.StartedAt = time.Now()
	}

	threatsJSON, err := json.Marshal(scan.Threats)
	if err != nil {
		return fmt.Errorf("failed to marshal threats: %w", err)
	}

	metadataJSON, err := json.Marshal(scan.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var query string
	if s.config.Type == "sqlite" {
		query = `
			INSERT INTO package_scans 
			(id, package_name, registry, version, status, risk_level, threats, summary, started_at, completed_at, duration, metadata)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
	} else {
		query = `
			INSERT INTO package_scans 
			(id, package_name, registry, version, status, risk_level, threats, summary, started_at, completed_at, duration, metadata)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`
	}

	_, err = s.db.ExecContext(ctx, query,
		scan.ID, scan.PackageName, scan.Registry, scan.Version, scan.Status,
		scan.RiskLevel, string(threatsJSON), scan.Summary, scan.StartedAt,
		scan.CompletedAt, scan.Duration, string(metadataJSON),
	)

	return err
}

// UpdateScan updates an existing scan record
func (s *OSSService) UpdateScan(ctx context.Context, scan *PackageScan) error {
	threatsJSON, err := json.Marshal(scan.Threats)
	if err != nil {
		return fmt.Errorf("failed to marshal threats: %w", err)
	}

	metadataJSON, err := json.Marshal(scan.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var query string
	if s.config.Type == "sqlite" {
		query = `
			UPDATE package_scans 
			SET status = ?, risk_level = ?, threats = ?, summary = ?, completed_at = ?, duration = ?, metadata = ?
			WHERE id = ?
		`
	} else {
		query = `
			UPDATE package_scans 
			SET status = $1, risk_level = $2, threats = $3, summary = $4, completed_at = $5, duration = $6, metadata = $7
			WHERE id = $8
		`
	}

	_, err = s.db.ExecContext(ctx, query,
		scan.Status, scan.RiskLevel, string(threatsJSON), scan.Summary,
		scan.CompletedAt, scan.Duration, string(metadataJSON), scan.ID,
	)

	return err
}

// GetScan retrieves a scan by ID
func (s *OSSService) GetScan(ctx context.Context, id string) (*PackageScan, error) {
	var query string
	if s.config.Type == "sqlite" {
		query = `
			SELECT id, package_name, registry, version, status, risk_level, threats, summary, 
			       started_at, completed_at, duration, metadata
			FROM package_scans 
			WHERE id = ?
		`
	} else {
		query = `
			SELECT id, package_name, registry, version, status, risk_level, threats, summary, 
			       started_at, completed_at, duration, metadata
			FROM package_scans 
			WHERE id = $1
		`
	}

	row := s.db.QueryRowContext(ctx, query, id)

	scan := &PackageScan{}
	var threatsJSON, metadataJSON string
	var version, riskLevel, summary sql.NullString
	var completedAt sql.NullTime
	var duration sql.NullInt64

	err := row.Scan(
		&scan.ID, &scan.PackageName, &scan.Registry, &version, &scan.Status,
		&riskLevel, &threatsJSON, &summary, &scan.StartedAt,
		&completedAt, &duration, &metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if version.Valid {
		scan.Version = version.String
	}
	if riskLevel.Valid {
		scan.RiskLevel = riskLevel.String
	}
	if summary.Valid {
		scan.Summary = summary.String
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}
	if duration.Valid {
		scan.Duration = duration.Int64
	}

	// Unmarshal JSON fields
	if threatsJSON != "" {
		if err := json.Unmarshal([]byte(threatsJSON), &scan.Threats); err != nil {
			return nil, fmt.Errorf("failed to unmarshal threats: %w", err)
		}
	}
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &scan.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return scan, nil
}

// GetRecentScans returns recent scan summaries
func (s *OSSService) GetRecentScans(ctx context.Context, limit int) ([]*ScanSummary, error) {
	var query string
	if s.config.Type == "sqlite" {
		query = `
			SELECT id, package_name, registry, status, risk_level, 
			       0 as threat_count,
			       duration, started_at, completed_at, threats
			FROM package_scans 
			ORDER BY started_at DESC 
			LIMIT ?
		`
	} else {
		query = `
			SELECT id, package_name, registry, status, risk_level, 
			       CASE 
			           WHEN threats IS NULL OR jsonb_typeof(threats) != 'array' THEN 0
			           ELSE jsonb_array_length(threats)
			       END as threat_count,
			       duration, started_at, completed_at, threats
			FROM package_scans 
			ORDER BY started_at DESC 
			LIMIT $1
		`
	}

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*ScanSummary
	for rows.Next() {
		scan := &ScanSummary{}
		var riskLevel sql.NullString
		var duration sql.NullInt64
		var completedAt sql.NullTime
		var threatsJSON sql.NullString

		err := rows.Scan(
			&scan.ID, &scan.PackageName, &scan.Registry, &scan.Status,
			&riskLevel, &scan.ThreatCount, &duration, &scan.StartedAt, &completedAt, &threatsJSON,
		)
		if err != nil {
			return nil, err
		}

		if riskLevel.Valid {
			scan.RiskLevel = riskLevel.String
		}
		if duration.Valid {
			scan.Duration = duration.Int64
		}
		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}

		// Parse threats JSON
		if threatsJSON.Valid && threatsJSON.String != "" {
			var threats []map[string]interface{}
			if err := json.Unmarshal([]byte(threatsJSON.String), &threats); err == nil {
				scan.Threats = threats
			}
		}

		scans = append(scans, scan)
	}

	return scans, rows.Err()
}

// SearchScans searches for scans by package name
func (s *OSSService) SearchScans(ctx context.Context, packageName string, limit int) ([]*ScanSummary, error) {
	var query string
	if s.config.Type == "sqlite" {
		query = `
			SELECT id, package_name, registry, status, risk_level, 
			       0 as threat_count,
			       duration, started_at, completed_at
			FROM package_scans 
			WHERE package_name LIKE ?
			ORDER BY started_at DESC 
			LIMIT ?
		`
	} else {
		query = `
			SELECT id, package_name, registry, status, risk_level, 
			       COALESCE(json_array_length(threats), 0) as threat_count,
			       duration, started_at, completed_at
			FROM package_scans 
			WHERE package_name LIKE $1
			ORDER BY started_at DESC 
			LIMIT $2
		`
	}

	rows, err := s.db.QueryContext(ctx, query, "%"+packageName+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*ScanSummary
	for rows.Next() {
		scan := &ScanSummary{}
		var riskLevel sql.NullString
		var duration sql.NullInt64
		var completedAt sql.NullTime

		err := rows.Scan(
			&scan.ID, &scan.PackageName, &scan.Registry, &scan.Status,
			&riskLevel, &scan.ThreatCount, &duration, &scan.StartedAt, &completedAt,
		)
		if err != nil {
			return nil, err
		}

		if riskLevel.Valid {
			scan.RiskLevel = riskLevel.String
		}
		if duration.Valid {
			scan.Duration = duration.Int64
		}
		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}

		scans = append(scans, scan)
	}

	return scans, rows.Err()
}

// GetScanStats returns basic statistics about scans
func (s *OSSService) GetScanStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total scans
	var totalScans int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM package_scans").Scan(&totalScans)
	if err != nil {
		return nil, err
	}
	stats["total_scans"] = totalScans

	// Scans by status
	statusQuery := `
		SELECT status, COUNT(*) 
		FROM package_scans 
		GROUP BY status
	`
	rows, err := s.db.QueryContext(ctx, statusQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		statusCounts[status] = count
	}
	stats["by_status"] = statusCounts

	// Scans by risk level
	riskQuery := `
		SELECT risk_level, COUNT(*) 
		FROM package_scans 
		WHERE risk_level IS NOT NULL
		GROUP BY risk_level
	`
	rows, err = s.db.QueryContext(ctx, riskQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	riskCounts := make(map[string]int)
	for rows.Next() {
		var riskLevel string
		var count int
		if err := rows.Scan(&riskLevel, &count); err != nil {
			return nil, err
		}
		riskCounts[riskLevel] = count
	}
	stats["by_risk_level"] = riskCounts

	return stats, nil
}

// GetDB returns the underlying database connection
func (s *OSSService) GetDB() *sql.DB {
	return s.db
}

// Close closes the database connection
func (s *OSSService) Close() error {
	return s.db.Close()
}
