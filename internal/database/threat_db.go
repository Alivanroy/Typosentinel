package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"

	_ "github.com/lib/pq"
)

// ThreatDB represents the PostgreSQL threat database
type ThreatDB struct {
	db     *sql.DB
	config *config.DatabaseConfig
}

// ThreatRecord represents a threat record in the database
type ThreatRecord struct {
	ID          int64     `json:"id"`
	PackageName string    `json:"package_name"`
	Registry    string    `json:"registry"`
	ThreatType  string    `json:"threat_type"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Metadata    string    `json:"metadata"` // JSON string for additional data
}

// ThreatPattern represents a threat detection pattern
type ThreatPattern struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"` // regex, exact, fuzzy
	ThreatType  string    `json:"threat_type"`
	Severity    string    `json:"severity"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewThreatDB creates a new threat database instance
func NewThreatDB(dbConfig *config.DatabaseConfig) (*ThreatDB, error) {
	// Open PostgreSQL database connection
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		dbConfig.Host, dbConfig.Port, dbConfig.Username, dbConfig.Password, dbConfig.Database, dbConfig.SSLMode)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	threatDB := &ThreatDB{
		db:     db,
		config: dbConfig,
	}

	// Initialize schema
	if err := threatDB.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return threatDB, nil
}

// initSchema creates the database tables if they don't exist
func (tdb *ThreatDB) initSchema() error {
	// Create threats table
	threatTableSQL := `
	CREATE TABLE IF NOT EXISTS threats (
		id BIGSERIAL PRIMARY KEY,
		package_name VARCHAR(255) NOT NULL,
		registry VARCHAR(100) NOT NULL,
		threat_type VARCHAR(100) NOT NULL,
		severity VARCHAR(50) NOT NULL,
		confidence DECIMAL(5,4) NOT NULL,
		description TEXT,
		source VARCHAR(255),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		metadata JSONB,
		UNIQUE(package_name, registry, threat_type)
	);
	`

	// Create threat patterns table
	patternTableSQL := `
	CREATE TABLE IF NOT EXISTS threat_patterns (
		id BIGSERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL UNIQUE,
		pattern TEXT NOT NULL,
		pattern_type VARCHAR(50) NOT NULL,
		threat_type VARCHAR(100) NOT NULL,
		severity VARCHAR(50) NOT NULL,
		enabled BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);
	`

	// Create indexes
	indexSQL := []string{
		`CREATE INDEX IF NOT EXISTS idx_threats_package ON threats(package_name);`,
		`CREATE INDEX IF NOT EXISTS idx_threats_registry ON threats(registry);`,
		`CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);`,
		`CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_patterns_type ON threat_patterns(pattern_type);`,
		`CREATE INDEX IF NOT EXISTS idx_patterns_enabled ON threat_patterns(enabled);`,
	}

	// Execute schema creation
	for _, sql := range []string{threatTableSQL, patternTableSQL} {
		if _, err := tdb.db.Exec(sql); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	// Create indexes
	for _, sql := range indexSQL {
		if _, err := tdb.db.Exec(sql); err != nil {
			log.Printf("Warning: failed to create index: %v", err)
		}
	}

	return nil
}

// AddThreat adds a new threat record to the database
func (tdb *ThreatDB) AddThreat(threat *ThreatRecord) error {
	query := `
		INSERT OR REPLACE INTO threats 
		(package_name, registry, threat_type, severity, confidence, description, source, metadata, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`

	_, err := tdb.db.Exec(query,
		threat.PackageName,
		threat.Registry,
		threat.ThreatType,
		threat.Severity,
		threat.Confidence,
		threat.Description,
		threat.Source,
		threat.Metadata,
	)

	return err
}

// GetThreat retrieves a threat by package name and registry
func (tdb *ThreatDB) GetThreat(packageName, registry string) (*ThreatRecord, error) {
	query := `
		SELECT id, package_name, registry, threat_type, severity, confidence, 
		       description, source, created_at, updated_at, metadata
		FROM threats 
		WHERE package_name = ? AND registry = ?
		ORDER BY severity DESC, confidence DESC
		LIMIT 1
	`

	row := tdb.db.QueryRow(query, packageName, registry)

	threat := &ThreatRecord{}
	err := row.Scan(
		&threat.ID,
		&threat.PackageName,
		&threat.Registry,
		&threat.ThreatType,
		&threat.Severity,
		&threat.Confidence,
		&threat.Description,
		&threat.Source,
		&threat.CreatedAt,
		&threat.UpdatedAt,
		&threat.Metadata,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	return threat, err
}

// GetThreats retrieves all threats matching the given criteria
func (tdb *ThreatDB) GetThreats(registry, threatType string, limit int) ([]*ThreatRecord, error) {
	query := `
		SELECT id, package_name, registry, threat_type, severity, confidence,
		       description, source, created_at, updated_at, metadata
		FROM threats
		WHERE 1=1
	`
	args := []interface{}{}

	if registry != "" {
		query += " AND registry = ?"
		args = append(args, registry)
	}

	if threatType != "" {
		query += " AND threat_type = ?"
		args = append(args, threatType)
	}

	query += " ORDER BY severity DESC, confidence DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := tdb.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []*ThreatRecord
	for rows.Next() {
		threat := &ThreatRecord{}
		err := rows.Scan(
			&threat.ID,
			&threat.PackageName,
			&threat.Registry,
			&threat.ThreatType,
			&threat.Severity,
			&threat.Confidence,
			&threat.Description,
			&threat.Source,
			&threat.CreatedAt,
			&threat.UpdatedAt,
			&threat.Metadata,
		)
		if err != nil {
			return nil, err
		}
		threats = append(threats, threat)
	}

	return threats, rows.Err()
}

// AddPattern adds a new threat detection pattern
func (tdb *ThreatDB) AddPattern(pattern *ThreatPattern) error {
	query := `
		INSERT OR REPLACE INTO threat_patterns
		(name, pattern, pattern_type, threat_type, severity, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`

	_, err := tdb.db.Exec(query,
		pattern.Name,
		pattern.Pattern,
		pattern.PatternType,
		pattern.ThreatType,
		pattern.Severity,
		pattern.Enabled,
	)

	return err
}

// GetPatterns retrieves all enabled threat patterns
func (tdb *ThreatDB) GetPatterns(patternType string) ([]*ThreatPattern, error) {
	query := `
		SELECT id, name, pattern, pattern_type, threat_type, severity, enabled,
		       created_at, updated_at
		FROM threat_patterns
		WHERE enabled = TRUE
	`
	args := []interface{}{}

	if patternType != "" {
		query += " AND pattern_type = ?"
		args = append(args, patternType)
	}

	query += " ORDER BY severity DESC"

	rows, err := tdb.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []*ThreatPattern
	for rows.Next() {
		pattern := &ThreatPattern{}
		err := rows.Scan(
			&pattern.ID,
			&pattern.Name,
			&pattern.Pattern,
			&pattern.PatternType,
			&pattern.ThreatType,
			&pattern.Severity,
			&pattern.Enabled,
			&pattern.CreatedAt,
			&pattern.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}

	return patterns, rows.Err()
}

// DeleteThreat removes a threat record
func (tdb *ThreatDB) DeleteThreat(packageName, registry string) error {
	query := "DELETE FROM threats WHERE package_name = ? AND registry = ?"
	_, err := tdb.db.Exec(query, packageName, registry)
	return err
}

// GetStats returns database statistics
func (tdb *ThreatDB) GetStats() (map[string]int, error) {
	stats := make(map[string]int)

	// Count total threats
	row := tdb.db.QueryRow("SELECT COUNT(*) FROM threats")
	var threatCount int
	if err := row.Scan(&threatCount); err != nil {
		return nil, err
	}
	stats["total_threats"] = threatCount

	// Count total patterns
	row = tdb.db.QueryRow("SELECT COUNT(*) FROM threat_patterns WHERE enabled = TRUE")
	var patternCount int
	if err := row.Scan(&patternCount); err != nil {
		return nil, err
	}
	stats["active_patterns"] = patternCount

	// Count by severity
	rows, err := tdb.db.Query("SELECT severity, COUNT(*) FROM threats GROUP BY severity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		stats[fmt.Sprintf("%s_threats", severity)] = count
	}

	return stats, nil
}

// Close closes the database connection
func (tdb *ThreatDB) Close() error {
	return tdb.db.Close()
}

// parseSeverity converts string severity to types.Severity
func parseSeverity(severity string) types.Severity {
	switch severity {
	case "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityLow
	}
}

// ConvertToThreat converts a ThreatRecord to types.Threat
func (tr *ThreatRecord) ConvertToThreat() *types.Threat {
	var metadata map[string]interface{}
	if tr.Metadata != "" {
		// Parse JSON metadata if available
		if err := json.Unmarshal([]byte(tr.Metadata), &metadata); err != nil {
			metadata = map[string]interface{}{"raw": tr.Metadata}
		}
	}

	return &types.Threat{
		ID:              fmt.Sprintf("%d", tr.ID),
		Package:         tr.PackageName,
		Type:            types.ThreatType(tr.ThreatType),
		Severity:        parseSeverity(tr.Severity),
		Confidence:      tr.Confidence,
		Description:     tr.Description,
		DetectedAt:      tr.CreatedAt,
		DetectionMethod: tr.Source,
		Metadata:        metadata,
	}
}
