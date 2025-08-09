package threat_intelligence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	_ "github.com/mattn/go-sqlite3"
)

// ThreatDatabase manages the storage and retrieval of threat intelligence data
type ThreatDatabase struct {
	db     *sql.DB
	logger *logger.Logger
	mu     sync.RWMutex
	stats  DatabaseStats
}

// DatabaseStats represents database statistics
type DatabaseStats struct {
	TotalThreats      int64            `json:"total_threats"`
	ThreatsByType     map[string]int64 `json:"threats_by_type"`
	ThreatsBySeverity map[string]int64 `json:"threats_by_severity"`
	ThreatsBySource   map[string]int64 `json:"threats_by_source"`
	LastUpdate        time.Time        `json:"last_update"`
	DatabaseSize      int64            `json:"database_size_bytes"`
}

// ThreatQuery represents a threat search query
type ThreatQuery struct {
	PackageName    string     `json:"package_name,omitempty"`
	Ecosystem      string     `json:"ecosystem,omitempty"`
	ThreatType     string     `json:"threat_type,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	Source         string     `json:"source,omitempty"`
	MinConfidence  float64    `json:"min_confidence,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
	Offset         int        `json:"offset,omitempty"`
	IncludeExpired bool       `json:"include_expired"`
}

// ThreatSearchResult represents the result of a threat search
type ThreatSearchResult struct {
	Threats   []ThreatIntelligence `json:"threats"`
	Total     int64                `json:"total"`
	Limit     int                  `json:"limit"`
	Offset    int                  `json:"offset"`
	QueryTime time.Duration        `json:"query_time"`
}

// NewThreatDatabase creates a new threat database instance
func NewThreatDatabase(logger *logger.Logger) *ThreatDatabase {
	return &ThreatDatabase{
		logger: logger,
		stats: DatabaseStats{
			ThreatsByType:     make(map[string]int64),
			ThreatsBySeverity: make(map[string]int64),
			ThreatsBySource:   make(map[string]int64),
		},
	}
}

// Initialize sets up the threat database
func (td *ThreatDatabase) Initialize(ctx context.Context) error {
	td.logger.Info("Initializing threat database")

	// Open SQLite database
	db, err := sql.Open("sqlite3", "threat_intelligence.db?cache=shared&mode=rwc")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Assign db with minimal locking
	td.mu.Lock()
	td.db = db
	td.mu.Unlock()

	// Configure database
	if err := td.configureDatabase(ctx); err != nil {
		return fmt.Errorf("failed to configure database: %w", err)
	}

	// Create tables
	if err := td.createTables(ctx); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Create indexes
	if err := td.createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	// Update statistics
	if err := td.updateStatistics(ctx); err != nil {
		td.logger.Warn("Failed to update initial statistics", map[string]interface{}{
			"error": err,
		})
	}

	td.logger.Info("Threat database initialized successfully")
	return nil
}

// StoreThreat stores a threat intelligence entry in the database
func (td *ThreatDatabase) StoreThreat(ctx context.Context, threat *ThreatIntelligence) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	// Serialize indicators and metadata
	indicatorsJSON, err := json.Marshal(threat.Indicators)
	if err != nil {
		return fmt.Errorf("failed to marshal indicators: %w", err)
	}

	metadataJSON, err := json.Marshal(threat.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	referencesJSON, err := json.Marshal(threat.References)
	if err != nil {
		return fmt.Errorf("failed to marshal references: %w", err)
	}

	tagsJSON, err := json.Marshal(threat.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	// Prepare expiration time
	var expiresAt *time.Time
	if threat.ExpiresAt != nil {
		expiresAt = threat.ExpiresAt
	}

	// Insert or update threat
	query := `
		INSERT OR REPLACE INTO threats (
			id, source, type, severity, package_name, ecosystem, description,
			indicators, "references", tags, confidence_level, first_seen, last_seen,
			expires_at, metadata, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	_, err = td.db.ExecContext(ctx, query,
		threat.ID, threat.Source, threat.Type, threat.Severity,
		threat.PackageName, threat.Ecosystem, threat.Description,
		indicatorsJSON, referencesJSON, tagsJSON, threat.ConfidenceLevel,
		threat.FirstSeen, threat.LastSeen, expiresAt, metadataJSON,
		now, now)

	if err != nil {
		return fmt.Errorf("failed to store threat: %w", err)
	}

	td.logger.Debug("Threat stored", map[string]interface{}{
		"threat_id": threat.ID,
		"package":   threat.PackageName,
	})
	return nil
}

// GetThreat retrieves a specific threat by ID
func (td *ThreatDatabase) GetThreat(ctx context.Context, threatID string) (*ThreatIntelligence, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	query := `
		SELECT id, source, type, severity, package_name, ecosystem, description,
		       indicators, "references", tags, confidence_level, first_seen, last_seen,
		       expires_at, metadata
		FROM threats
		WHERE id = ? AND (expires_at IS NULL OR expires_at > ?)
	`

	row := td.db.QueryRowContext(ctx, query, threatID, time.Now())

	threat, err := td.scanThreat(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("threat not found: %s", threatID)
		}
		return nil, fmt.Errorf("failed to get threat: %w", err)
	}

	return threat, nil
}

// SearchThreats searches for threats based on the provided query
func (td *ThreatDatabase) SearchThreats(ctx context.Context, query *ThreatQuery) (*ThreatSearchResult, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	start := time.Now()

	// Build SQL query
	sqlQuery, args := td.buildSearchQuery(query)

	// Execute count query
	// Derive a robust COUNT query by taking the portion from FROM ... and stripping ORDER BY/LIMIT
	countQueryBase := sqlQuery
	// Strip ORDER BY (case-insensitive)
	if idx := strings.Index(strings.ToUpper(countQueryBase), "ORDER BY"); idx != -1 {
		countQueryBase = countQueryBase[:idx]
	}
	// Strip LIMIT (case-insensitive)
	if idx := strings.Index(strings.ToUpper(countQueryBase), "LIMIT"); idx != -1 {
		countQueryBase = countQueryBase[:idx]
	}
	// Find FROM clause (case-insensitive)
	fromIdx := strings.Index(strings.ToUpper(countQueryBase), "FROM ")
	if fromIdx == -1 {
		return nil, fmt.Errorf("invalid search query: missing FROM")
	}
	countQuery := "SELECT COUNT(*) " + countQueryBase[fromIdx:]

	var total int64
	argsNoPag := args
	if len(argsNoPag) >= 2 {
		argsNoPag = argsNoPag[:len(argsNoPag)-2] // Remove LIMIT and OFFSET args
	}
	err := td.db.QueryRowContext(ctx, countQuery, argsNoPag...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("failed to count threats: %w", err)
	}

	// Execute main query
	rows, err := td.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search threats: %w", err)
	}
	defer rows.Close()

	var threats []ThreatIntelligence
	for rows.Next() {
		threat, err := td.scanThreat(rows)
		if err != nil {
			td.logger.Warn("Failed to scan threat", map[string]interface{}{
				"error": err,
			})
			continue
		}
		threats = append(threats, *threat)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating threats: %w", err)
	}

	limit := query.Limit
	if limit == 0 {
		limit = 100 // Default limit
	}

	return &ThreatSearchResult{
		Threats:   threats,
		Total:     total,
		Limit:     limit,
		Offset:    query.Offset,
		QueryTime: time.Since(start),
	}, nil
}

// GetThreatsForPackage retrieves all threats for a specific package
func (td *ThreatDatabase) GetThreatsForPackage(ctx context.Context, packageName, ecosystem string) ([]ThreatIntelligence, error) {
	query := &ThreatQuery{
		PackageName: packageName,
		Ecosystem:   ecosystem,
		Limit:       1000,
	}

	result, err := td.SearchThreats(ctx, query)
	if err != nil {
		return nil, err
	}

	return result.Threats, nil
}

// RemoveThreat removes a threat from the database
func (td *ThreatDatabase) RemoveThreat(ctx context.Context, threatID string) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	query := "DELETE FROM threats WHERE id = ?"
	result, err := td.db.ExecContext(ctx, query, threatID)
	if err != nil {
		return fmt.Errorf("failed to remove threat: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("threat not found: %s", threatID)
	}

	td.logger.Debug("Threat removed", map[string]interface{}{
		"threat_id": threatID,
	})
	return nil
}

// CleanupExpiredThreats removes expired threats from the database
func (td *ThreatDatabase) CleanupExpiredThreats(ctx context.Context) (int64, error) {
	td.mu.Lock()
	defer td.mu.Unlock()

	query := "DELETE FROM threats WHERE expires_at IS NOT NULL AND expires_at <= ?"
	result, err := td.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired threats: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	td.logger.Info("Expired threats cleaned up", map[string]interface{}{
		"count": rowsAffected,
	})
	return rowsAffected, nil
}

// GetStatistics returns database statistics
func (td *ThreatDatabase) GetStatistics() DatabaseStats {
	td.mu.RLock()
	defer td.mu.RUnlock()
	return td.stats
}

// UpdateStatistics updates database statistics
func (td *ThreatDatabase) UpdateStatistics(ctx context.Context) error {
	return td.updateStatistics(ctx)
}

// Close closes the database connection
func (td *ThreatDatabase) Close() error {
	td.mu.Lock()
	defer td.mu.Unlock()

	if td.db != nil {
		return td.db.Close()
	}
	return nil
}

// Helper methods

func (td *ThreatDatabase) configureDatabase(ctx context.Context) error {
	// Set SQLite pragmas for performance
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = 10000",
		"PRAGMA temp_store = memory",
		"PRAGMA mmap_size = 268435456", // 256MB
	}

	for _, pragma := range pragmas {
		if _, err := td.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("failed to execute pragma %s: %w", pragma, err)
		}
	}

	return nil
}

func (td *ThreatDatabase) createTables(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS threats (
			id TEXT PRIMARY KEY,
			source TEXT NOT NULL,
			type TEXT NOT NULL,
			severity TEXT NOT NULL,
			package_name TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			description TEXT,
			indicators TEXT, -- JSON
			"references" TEXT, -- JSON
			tags TEXT, -- JSON
			confidence_level REAL NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			expires_at DATETIME,
			metadata TEXT, -- JSON
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)
	`

	if _, err := td.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to create threats table: %w", err)
	}

	return nil
}

func (td *ThreatDatabase) createIndexes(ctx context.Context) error {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_threats_package_ecosystem ON threats(package_name, ecosystem)",
		"CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(type)",
		"CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)",
		"CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source)",
		"CREATE INDEX IF NOT EXISTS idx_threats_confidence ON threats(confidence_level)",
		"CREATE INDEX IF NOT EXISTS idx_threats_first_seen ON threats(first_seen)",
		"CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats(last_seen)",
		"CREATE INDEX IF NOT EXISTS idx_threats_expires_at ON threats(expires_at)",
	}

	for _, index := range indexes {
		if _, err := td.db.ExecContext(ctx, index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

func (td *ThreatDatabase) buildSearchQuery(query *ThreatQuery) (string, []interface{}) {
	sql := `
		SELECT id, source, type, severity, package_name, ecosystem, description,
		       indicators, "references", tags, confidence_level, first_seen, last_seen,
		       expires_at, metadata
		FROM threats
		WHERE 1=1
	`

	var args []interface{}

	// Add expiration filter unless explicitly including expired
	if !query.IncludeExpired {
		sql += " AND (expires_at IS NULL OR expires_at > ?)"
		args = append(args, time.Now())
	}

	// Add filters
	if query.PackageName != "" {
		sql += " AND package_name = ?"
		args = append(args, query.PackageName)
	}

	if query.Ecosystem != "" {
		sql += " AND ecosystem = ?"
		args = append(args, query.Ecosystem)
	}

	if query.ThreatType != "" {
		sql += " AND type = ?"
		args = append(args, query.ThreatType)
	}

	if query.Severity != "" {
		sql += " AND severity = ?"
		args = append(args, query.Severity)
	}

	if query.Source != "" {
		sql += " AND source = ?"
		args = append(args, query.Source)
	}

	if query.MinConfidence > 0 {
		sql += " AND confidence_level >= ?"
		args = append(args, query.MinConfidence)
	}

	if query.Since != nil {
		sql += " AND first_seen >= ?"
		args = append(args, *query.Since)
	}

	if query.Until != nil {
		sql += " AND first_seen <= ?"
		args = append(args, *query.Until)
	}

	// Add ordering
	sql += " ORDER BY first_seen DESC"

	// Add pagination
	limit := query.Limit
	if limit == 0 {
		limit = 100 // Default limit
	}
	sql += " LIMIT ? OFFSET ?"
	args = append(args, limit, query.Offset)

	return sql, args
}

func (td *ThreatDatabase) scanThreat(scanner interface{}) (*ThreatIntelligence, error) {
	var threat ThreatIntelligence
	var indicatorsJSON, referencesJSON, tagsJSON, metadataJSON string
	var expiresAt *time.Time

	var err error
	switch s := scanner.(type) {
	case *sql.Row:
		err = s.Scan(
			&threat.ID, &threat.Source, &threat.Type, &threat.Severity,
			&threat.PackageName, &threat.Ecosystem, &threat.Description,
			&indicatorsJSON, &referencesJSON, &tagsJSON, &threat.ConfidenceLevel,
			&threat.FirstSeen, &threat.LastSeen, &expiresAt, &metadataJSON,
		)
	case *sql.Rows:
		err = s.Scan(
			&threat.ID, &threat.Source, &threat.Type, &threat.Severity,
			&threat.PackageName, &threat.Ecosystem, &threat.Description,
			&indicatorsJSON, &referencesJSON, &tagsJSON, &threat.ConfidenceLevel,
			&threat.FirstSeen, &threat.LastSeen, &expiresAt, &metadataJSON,
		)
	default:
		return nil, fmt.Errorf("unsupported scanner type")
	}

	if err != nil {
		return nil, err
	}

	threat.ExpiresAt = expiresAt

	// Unmarshal JSON fields
	if err := json.Unmarshal([]byte(indicatorsJSON), &threat.Indicators); err != nil {
		td.logger.Warn("Failed to unmarshal indicators", map[string]interface{}{
			"threat_id": threat.ID,
			"error":     err,
		})
		threat.Indicators = []ThreatIndicator{}
	}

	if err := json.Unmarshal([]byte(referencesJSON), &threat.References); err != nil {
		td.logger.Warn("Failed to unmarshal references", map[string]interface{}{
			"threat_id": threat.ID,
			"error":     err,
		})
		threat.References = []string{}
	}

	if err := json.Unmarshal([]byte(tagsJSON), &threat.Tags); err != nil {
		td.logger.Warn("Failed to unmarshal tags", map[string]interface{}{
			"threat_id": threat.ID,
			"error":     err,
		})
		threat.Tags = []string{}
	}

	if err := json.Unmarshal([]byte(metadataJSON), &threat.Metadata); err != nil {
		td.logger.Warn("Failed to unmarshal metadata", map[string]interface{}{
			"threat_id": threat.ID,
			"error":     err,
		})
		threat.Metadata = make(map[string]interface{})
	}

	return &threat, nil
}

func (td *ThreatDatabase) updateStatistics(ctx context.Context) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	// Update total threats
	var total int64
	err := td.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threats WHERE expires_at IS NULL OR expires_at > ?", time.Now()).Scan(&total)
	if err != nil {
		return fmt.Errorf("failed to count total threats: %w", err)
	}
	td.stats.TotalThreats = total

	// Update threats by type
	rows, err := td.db.QueryContext(ctx, "SELECT type, COUNT(*) FROM threats WHERE expires_at IS NULL OR expires_at > ? GROUP BY type", time.Now())
	if err != nil {
		return fmt.Errorf("failed to count threats by type: %w", err)
	}
	defer rows.Close()

	td.stats.ThreatsByType = make(map[string]int64)
	for rows.Next() {
		var threatType string
		var count int64
		if err := rows.Scan(&threatType, &count); err != nil {
			continue
		}
		td.stats.ThreatsByType[threatType] = count
	}

	// Update threats by severity
	rows, err = td.db.QueryContext(ctx, "SELECT severity, COUNT(*) FROM threats WHERE expires_at IS NULL OR expires_at > ? GROUP BY severity", time.Now())
	if err != nil {
		return fmt.Errorf("failed to count threats by severity: %w", err)
	}
	defer rows.Close()

	td.stats.ThreatsBySeverity = make(map[string]int64)
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			continue
		}
		td.stats.ThreatsBySeverity[severity] = count
	}

	// Update threats by source
	rows, err = td.db.QueryContext(ctx, "SELECT source, COUNT(*) FROM threats WHERE expires_at IS NULL OR expires_at > ? GROUP BY source", time.Now())
	if err != nil {
		return fmt.Errorf("failed to count threats by source: %w", err)
	}
	defer rows.Close()

	td.stats.ThreatsBySource = make(map[string]int64)
	for rows.Next() {
		var source string
		var count int64
		if err := rows.Scan(&source, &count); err != nil {
			continue
		}
		td.stats.ThreatsBySource[source] = count
	}

	td.stats.LastUpdate = time.Now()

	return nil
}
