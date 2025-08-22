package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// DatabaseService provides CRUD operations for the database
type DatabaseService struct {
	db     *sql.DB
	config *config.DatabaseConfig
}

// Organization represents an organization record
type Organization struct {
	ID          string                 `json:"id"`
	Platform    string                 `json:"platform"`
	Login       string                 `json:"login"`
	Name        *string                `json:"name"`
	Description *string                `json:"description"`
	HTMLURL     *string                `json:"html_url"`
	AvatarURL   *string                `json:"avatar_url"`
	Type        string                 `json:"type"`
	Location    *string                `json:"location"`
	Email       *string                `json:"email"`
	Blog        *string                `json:"blog"`
	Twitter     *string                `json:"twitter"`
	Company     *string                `json:"company"`
	PublicRepos int                    `json:"public_repos"`
	PublicGists int                    `json:"public_gists"`
	Followers   int                    `json:"followers"`
	Following   int                    `json:"following"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ScanStatus  string                 `json:"scan_status"`
	LastScanAt  *time.Time             `json:"last_scan_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Repository represents a repository record
type Repository struct {
	ID            string                 `json:"id"`
	Platform      string                 `json:"platform"`
	OrgID         *string                `json:"org_id"`
	Owner         string                 `json:"owner"`
	Name          string                 `json:"name"`
	FullName      string                 `json:"full_name"`
	Description   *string                `json:"description"`
	HTMLURL       string                 `json:"html_url"`
	CloneURL      string                 `json:"clone_url"`
	SSHURL        string                 `json:"ssh_url"`
	Homepage      *string                `json:"homepage"`
	Language      *string                `json:"language"`
	IsPrivate     bool                   `json:"is_private"`
	IsFork        bool                   `json:"is_fork"`
	IsArchived    bool                   `json:"is_archived"`
	IsDisabled    bool                   `json:"is_disabled"`
	Size          int64                  `json:"size"`
	StarsCount    int                    `json:"stars_count"`
	WatchersCount int                    `json:"watchers_count"`
	ForksCount    int                    `json:"forks_count"`
	IssuesCount   int                    `json:"issues_count"`
	Topics        []string               `json:"topics"`
	Branches      []string               `json:"branches"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	PushedAt      *time.Time             `json:"pushed_at"`
	ScanStatus    string                 `json:"scan_status"`
	LastScanAt    *time.Time             `json:"last_scan_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ScanJob represents a scan job record
type ScanJob struct {
	ID             string                 `json:"id"`
	OrgID          string                 `json:"org_id"`
	JobType        string                 `json:"job_type"`
	Configuration  map[string]interface{} `json:"configuration"`
	Status         string                 `json:"status"`
	Progress       float64                `json:"progress"`
	StartedAt      *time.Time             `json:"started_at"`
	CompletedAt    *time.Time             `json:"completed_at"`
	EstimatedTime  *time.Duration         `json:"estimated_time"`
	ActualTime     *time.Duration         `json:"actual_time"`
	TotalRepos     int                    `json:"total_repos"`
	ScannedRepos   int                    `json:"scanned_repos"`
	FailedRepos    int                    `json:"failed_repos"`
	TotalThreats   int                    `json:"total_threats"`
	CriticalThreats int                   `json:"critical_threats"`
	HighThreats    int                    `json:"high_threats"`
	MediumThreats  int                    `json:"medium_threats"`
	LowThreats     int                    `json:"low_threats"`
	WorkerID       *string                `json:"worker_id"`
	RetryCount     int                    `json:"retry_count"`
	MaxRetries     int                    `json:"max_retries"`
	ErrorMessage   *string                `json:"error_message"`
	ErrorDetails   map[string]interface{} `json:"error_details"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// NewDatabaseService creates a new database service
func NewDatabaseService(dbConfig *config.DatabaseConfig) (*DatabaseService, error) {
	if dbConfig == nil {
		return nil, fmt.Errorf("database config cannot be nil")
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		dbConfig.Host, dbConfig.Port, dbConfig.Username, dbConfig.Password, dbConfig.Database, dbConfig.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	if dbConfig.MaxOpenConns > 0 {
		db.SetMaxOpenConns(dbConfig.MaxOpenConns)
	}
	if dbConfig.MaxIdleConns > 0 {
		db.SetMaxIdleConns(dbConfig.MaxIdleConns)
	}
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DatabaseService{
		db:     db,
		config: dbConfig,
	}, nil
}

// GetDB returns the underlying database connection
func (ds *DatabaseService) GetDB() *sql.DB {
	return ds.db
}

// Close closes the database connection
func (ds *DatabaseService) Close() error {
	return ds.db.Close()
}

// CreateOrganization creates a new organization record
func (ds *DatabaseService) CreateOrganization(ctx context.Context, org *Organization) error {
	if org.ID == "" {
		org.ID = uuid.New().String()
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now()
	}
	org.UpdatedAt = time.Now()

	metadataJSON, err := json.Marshal(org.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO organizations (
			id, platform, login, name, description, html_url, avatar_url, type,
			location, email, blog, twitter, company, public_repos, public_gists,
			followers, following, created_at, updated_at, scan_status, last_scan_at, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
		)
	`

	_, err = ds.db.ExecContext(ctx, query,
		org.ID, org.Platform, org.Login, org.Name, org.Description, org.HTMLURL, org.AvatarURL, org.Type,
		org.Location, org.Email, org.Blog, org.Twitter, org.Company, org.PublicRepos, org.PublicGists,
		org.Followers, org.Following, org.CreatedAt, org.UpdatedAt, org.ScanStatus, org.LastScanAt, metadataJSON,
	)

	return err
}

// GetOrganization retrieves an organization by platform and login
func (ds *DatabaseService) GetOrganization(ctx context.Context, platform, login string) (*Organization, error) {
	query := `
		SELECT id, platform, login, name, description, html_url, avatar_url, type,
		       location, email, blog, twitter, company, public_repos, public_gists,
		       followers, following, created_at, updated_at, scan_status, last_scan_at, metadata
		FROM organizations
		WHERE platform = $1 AND login = $2
	`

	row := ds.db.QueryRowContext(ctx, query, platform, login)

	org := &Organization{}
	var metadataJSON []byte

	err := row.Scan(
		&org.ID, &org.Platform, &org.Login, &org.Name, &org.Description, &org.HTMLURL, &org.AvatarURL, &org.Type,
		&org.Location, &org.Email, &org.Blog, &org.Twitter, &org.Company, &org.PublicRepos, &org.PublicGists,
		&org.Followers, &org.Following, &org.CreatedAt, &org.UpdatedAt, &org.ScanStatus, &org.LastScanAt, &metadataJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &org.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return org, nil
}

// CreateRepository creates a new repository record
func (ds *DatabaseService) CreateRepository(ctx context.Context, repo *Repository) error {
	if repo.ID == "" {
		repo.ID = uuid.New().String()
	}
	if repo.CreatedAt.IsZero() {
		repo.CreatedAt = time.Now()
	}
	repo.UpdatedAt = time.Now()

	metadataJSON, err := json.Marshal(repo.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	topicsJSON, err := json.Marshal(repo.Topics)
	if err != nil {
		return fmt.Errorf("failed to marshal topics: %w", err)
	}

	branchesJSON, err := json.Marshal(repo.Branches)
	if err != nil {
		return fmt.Errorf("failed to marshal branches: %w", err)
	}

	query := `
		INSERT INTO repositories (
			id, platform, org_id, owner, name, full_name, description, html_url, clone_url, ssh_url,
			homepage, language, is_private, is_fork, is_archived, is_disabled, size, stars_count,
			watchers_count, forks_count, issues_count, topics, branches, created_at, updated_at,
			pushed_at, scan_status, last_scan_at, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29
		)
	`

	_, err = ds.db.ExecContext(ctx, query,
		repo.ID, repo.Platform, repo.OrgID, repo.Owner, repo.Name, repo.FullName, repo.Description,
		repo.HTMLURL, repo.CloneURL, repo.SSHURL, repo.Homepage, repo.Language, repo.IsPrivate,
		repo.IsFork, repo.IsArchived, repo.IsDisabled, repo.Size, repo.StarsCount, repo.WatchersCount,
		repo.ForksCount, repo.IssuesCount, topicsJSON, branchesJSON, repo.CreatedAt, repo.UpdatedAt,
		repo.PushedAt, repo.ScanStatus, repo.LastScanAt, metadataJSON,
	)

	return err
}

// GetRepositoriesByOrganization retrieves repositories for an organization
func (ds *DatabaseService) GetRepositoriesByOrganization(ctx context.Context, orgID string, limit, offset int) ([]*Repository, error) {
	query := `
		SELECT id, platform, org_id, owner, name, full_name, description, html_url, clone_url, ssh_url,
		       homepage, language, is_private, is_fork, is_archived, is_disabled, size, stars_count,
		       watchers_count, forks_count, issues_count, topics, branches, created_at, updated_at,
		       pushed_at, scan_status, last_scan_at, metadata
		FROM repositories
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := ds.db.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repositories []*Repository
	for rows.Next() {
		repo := &Repository{}
		var metadataJSON, topicsJSON, branchesJSON []byte

		err := rows.Scan(
			&repo.ID, &repo.Platform, &repo.OrgID, &repo.Owner, &repo.Name, &repo.FullName, &repo.Description,
			&repo.HTMLURL, &repo.CloneURL, &repo.SSHURL, &repo.Homepage, &repo.Language, &repo.IsPrivate,
			&repo.IsFork, &repo.IsArchived, &repo.IsDisabled, &repo.Size, &repo.StarsCount, &repo.WatchersCount,
			&repo.ForksCount, &repo.IssuesCount, &topicsJSON, &branchesJSON, &repo.CreatedAt, &repo.UpdatedAt,
			&repo.PushedAt, &repo.ScanStatus, &repo.LastScanAt, &metadataJSON,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal JSON fields
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &repo.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}
		if len(topicsJSON) > 0 {
			if err := json.Unmarshal(topicsJSON, &repo.Topics); err != nil {
				return nil, fmt.Errorf("failed to unmarshal topics: %w", err)
			}
		}
		if len(branchesJSON) > 0 {
			if err := json.Unmarshal(branchesJSON, &repo.Branches); err != nil {
				return nil, fmt.Errorf("failed to unmarshal branches: %w", err)
			}
		}

		repositories = append(repositories, repo)
	}

	return repositories, rows.Err()
}

// CreateScanJob creates a new scan job record
func (ds *DatabaseService) CreateScanJob(ctx context.Context, job *ScanJob) error {
	if job.ID == "" {
		job.ID = uuid.New().String()
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now()
	}
	job.UpdatedAt = time.Now()

	configJSON, err := json.Marshal(job.Configuration)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	errorDetailsJSON, err := json.Marshal(job.ErrorDetails)
	if err != nil {
		return fmt.Errorf("failed to marshal error details: %w", err)
	}

	metadataJSON, err := json.Marshal(job.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO scan_jobs (
			id, org_id, job_type, configuration, status, progress, started_at, completed_at,
			estimated_time, actual_time, total_repos, scanned_repos, failed_repos, total_threats,
			critical_threats, high_threats, medium_threats, low_threats, worker_id, retry_count,
			max_retries, error_message, error_details, created_at, updated_at, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
		)
	`

	_, err = ds.db.ExecContext(ctx, query,
		job.ID, job.OrgID, job.JobType, configJSON, job.Status, job.Progress, job.StartedAt, job.CompletedAt,
		job.EstimatedTime, job.ActualTime, job.TotalRepos, job.ScannedRepos, job.FailedRepos, job.TotalThreats,
		job.CriticalThreats, job.HighThreats, job.MediumThreats, job.LowThreats, job.WorkerID, job.RetryCount,
		job.MaxRetries, job.ErrorMessage, errorDetailsJSON, job.CreatedAt, job.UpdatedAt, metadataJSON,
	)

	return err
}

// UpdateScanJobStatus updates the status and progress of a scan job
func (ds *DatabaseService) UpdateScanJobStatus(ctx context.Context, jobID, status string, progress float64) error {
	query := `
		UPDATE scan_jobs
		SET status = $2, progress = $3, updated_at = $4
		WHERE id = $1
	`

	_, err := ds.db.ExecContext(ctx, query, jobID, status, progress, time.Now())
	return err
}

// GetScanJob retrieves a scan job by ID
func (ds *DatabaseService) GetScanJob(ctx context.Context, jobID string) (*ScanJob, error) {
	query := `
		SELECT id, org_id, job_type, configuration, status, progress, started_at, completed_at,
		       estimated_time, actual_time, total_repos, scanned_repos, failed_repos, total_threats,
		       critical_threats, high_threats, medium_threats, low_threats, worker_id, retry_count,
		       max_retries, error_message, error_details, created_at, updated_at, metadata
		FROM scan_jobs
		WHERE id = $1
	`

	row := ds.db.QueryRowContext(ctx, query, jobID)

	job := &ScanJob{}
	var configJSON, errorDetailsJSON, metadataJSON []byte

	err := row.Scan(
		&job.ID, &job.OrgID, &job.JobType, &configJSON, &job.Status, &job.Progress, &job.StartedAt, &job.CompletedAt,
		&job.EstimatedTime, &job.ActualTime, &job.TotalRepos, &job.ScannedRepos, &job.FailedRepos, &job.TotalThreats,
		&job.CriticalThreats, &job.HighThreats, &job.MediumThreats, &job.LowThreats, &job.WorkerID, &job.RetryCount,
		&job.MaxRetries, &job.ErrorMessage, &errorDetailsJSON, &job.CreatedAt, &job.UpdatedAt, &metadataJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	// Unmarshal JSON fields
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &job.Configuration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
		}
	}
	if len(errorDetailsJSON) > 0 {
		if err := json.Unmarshal(errorDetailsJSON, &job.ErrorDetails); err != nil {
			return nil, fmt.Errorf("failed to unmarshal error details: %w", err)
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &job.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return job, nil
}

// HealthCheck performs a database health check
func (ds *DatabaseService) HealthCheck(ctx context.Context) error {
	return ds.db.PingContext(ctx)
}

// ScanJobStats represents scan job statistics
type ScanJobStats struct {
	TotalScans     int64 `json:"total_scans"`
	CompletedScans int64 `json:"completed_scans"`
	FailedScans    int64 `json:"failed_scans"`
	RunningScans   int64 `json:"running_scans"`
}

// ThreatStats represents threat statistics
type ThreatStats struct {
	TotalThreats     int64   `json:"total_threats"`
	CriticalThreats  int64   `json:"critical_threats"`
	HighThreats      int64   `json:"high_threats"`
	MediumThreats    int64   `json:"medium_threats"`
	LowThreats       int64   `json:"low_threats"`
	AverageRiskScore float64 `json:"average_risk_score"`
}

// GetRepositoryCount returns the total number of repositories
func (ds *DatabaseService) GetRepositoryCount(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM repositories`
	var count int64
	err := ds.db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

// GetScanJobStats returns scan job statistics
func (ds *DatabaseService) GetScanJobStats(ctx context.Context) (*ScanJobStats, error) {
	stats := &ScanJobStats{}
	
	// Get total scans
	err := ds.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_jobs`).Scan(&stats.TotalScans)
	if err != nil {
		return nil, err
	}
	
	// Get completed scans
	err = ds.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_jobs WHERE status = 'completed'`).Scan(&stats.CompletedScans)
	if err != nil {
		return nil, err
	}
	
	// Get failed scans
	err = ds.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_jobs WHERE status = 'failed'`).Scan(&stats.FailedScans)
	if err != nil {
		return nil, err
	}
	
	// Get running scans
	err = ds.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'`).Scan(&stats.RunningScans)
	if err != nil {
		return nil, err
	}
	
	return stats, nil
}

// GetThreatStats returns threat statistics
func (ds *DatabaseService) GetThreatStats(ctx context.Context) (*ThreatStats, error) {
	stats := &ThreatStats{}
	
	// Get total threats from scan jobs
	err := ds.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_threats), 0) FROM scan_jobs`).Scan(&stats.TotalThreats)
	if err != nil {
		return nil, err
	}
	
	// Get critical threats
	err = ds.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(critical_threats), 0) FROM scan_jobs`).Scan(&stats.CriticalThreats)
	if err != nil {
		return nil, err
	}
	
	// Get high threats
	err = ds.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(high_threats), 0) FROM scan_jobs`).Scan(&stats.HighThreats)
	if err != nil {
		return nil, err
	}
	
	// Get medium threats
	err = ds.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(medium_threats), 0) FROM scan_jobs`).Scan(&stats.MediumThreats)
	if err != nil {
		return nil, err
	}
	
	// Get low threats
	err = ds.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(low_threats), 0) FROM scan_jobs`).Scan(&stats.LowThreats)
	if err != nil {
		return nil, err
	}
	
	// Calculate average risk score (simplified)
	if stats.TotalThreats > 0 {
		criticalWeight := float64(stats.CriticalThreats) * 1.0
		highWeight := float64(stats.HighThreats) * 0.8
		mediumWeight := float64(stats.MediumThreats) * 0.6
		lowWeight := float64(stats.LowThreats) * 0.3
		
		stats.AverageRiskScore = (criticalWeight + highWeight + mediumWeight + lowWeight) / float64(stats.TotalThreats)
	}
	
	return stats, nil
}

// GetThreatTrend returns threat trend data (simplified implementation)
func (ds *DatabaseService) GetThreatTrend(ctx context.Context, duration time.Duration) (float64, error) {
	// Simple implementation: compare last 7 days vs previous 7 days
	query := `
		SELECT 
			COALESCE(SUM(CASE WHEN created_at >= NOW() - INTERVAL '7 days' THEN total_threats ELSE 0 END), 0) as recent,
			COALESCE(SUM(CASE WHEN created_at >= NOW() - INTERVAL '14 days' AND created_at < NOW() - INTERVAL '7 days' THEN total_threats ELSE 0 END), 0) as previous
		FROM scan_jobs
	`
	
	var recent, previous int64
	err := ds.db.QueryRowContext(ctx, query).Scan(&recent, &previous)
	if err != nil {
		return 0, err
	}
	
	if previous == 0 {
		if recent > 0 {
			return 100.0, nil // 100% increase if no previous data
		}
		return 0.0, nil
	}
	
	trend := float64(recent-previous) / float64(previous) * 100
	return trend, nil
}

// GetLastScanTime returns the timestamp of the last scan
func (ds *DatabaseService) GetLastScanTime(ctx context.Context) (*time.Time, error) {
	query := `SELECT MAX(completed_at) FROM scan_jobs WHERE status = 'completed'`
	var lastScan *time.Time
	err := ds.db.QueryRowContext(ctx, query).Scan(&lastScan)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return lastScan, nil
}

// GetRepositoryPlatformStats returns repository statistics by platform
func (ds *DatabaseService) GetRepositoryPlatformStats(ctx context.Context) (map[string]int64, error) {
	query := `SELECT platform, COUNT(*) FROM repositories GROUP BY platform`
	rows, err := ds.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	stats := make(map[string]int64)
	for rows.Next() {
		var platform string
		var count int64
		if err := rows.Scan(&platform, &count); err != nil {
			return nil, err
		}
		stats[platform] = count
	}
	
	return stats, rows.Err()
}

// GetThreatsByType returns threat counts by type (simplified implementation)
func (ds *DatabaseService) GetThreatsByType() (map[string]int64, error) {
	// Since we don't have a threats table, we'll return a simplified breakdown
	// based on the threat counts in scan_jobs
	ctx := context.Background()
	stats, err := ds.GetThreatStats(ctx)
	if err != nil {
		return nil, err
	}
	
	threatsByType := map[string]int64{
		"critical": stats.CriticalThreats,
		"high":     stats.HighThreats,
		"medium":   stats.MediumThreats,
		"low":      stats.LowThreats,
	}
	
	return threatsByType, nil
}

// EnterpriseScanSummary represents a summary of an enterprise scan
type EnterpriseScanSummary struct {
	ID          string    `json:"id"`
	JobType     string    `json:"job_type"`
	Status      string    `json:"status"`
	ThreatCount int64     `json:"threat_count"`
	Duration    int64     `json:"duration"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// TrendDataPoint represents a data point in a trend
type TrendDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label"`
}

// ThreatSummary represents a summary of threats
type ThreatSummary struct {
	Type        string `json:"type"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// GetRepositoryLanguageStats returns language statistics for repositories
func (ds *DatabaseService) GetRepositoryLanguageStats(ctx context.Context) (map[string]int64, error) {
	query := `SELECT language, COUNT(*) FROM repositories WHERE language IS NOT NULL AND language != '' GROUP BY language ORDER BY COUNT(*) DESC`
	rows, err := ds.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	stats := make(map[string]int64)
	for rows.Next() {
		var language string
		var count int64
		if err := rows.Scan(&language, &count); err != nil {
			return nil, err
		}
		stats[language] = count
	}
	
	return stats, rows.Err()
}

// GetRecentScans returns recent scan summaries
func (ds *DatabaseService) GetRecentScans(ctx context.Context, limit int) ([]*EnterpriseScanSummary, error) {
	query := `
		SELECT id, job_type, status, total_threats, 
		       EXTRACT(EPOCH FROM (completed_at - started_at)) as duration,
		       started_at, completed_at
		FROM scan_jobs 
		WHERE completed_at IS NOT NULL
		ORDER BY completed_at DESC 
		LIMIT $1
	`
	
	rows, err := ds.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var scans []*EnterpriseScanSummary
	for rows.Next() {
		scan := &EnterpriseScanSummary{}
		var duration *float64
		
		err := rows.Scan(&scan.ID, &scan.JobType, &scan.Status, &scan.ThreatCount, 
			&duration, &scan.StartedAt, &scan.CompletedAt)
		if err != nil {
			return nil, err
		}
		
		if duration != nil {
			scan.Duration = int64(*duration)
		}
		
		scans = append(scans, scan)
	}
	
	return scans, rows.Err()
}

// GetScanTrends returns scan trend data
func (ds *DatabaseService) GetScanTrends(ctx context.Context, duration time.Duration, points int) ([]*TrendDataPoint, error) {
	// Generate trend data based on scan history
	query := `
		SELECT DATE_TRUNC('hour', completed_at) as hour, COUNT(*) as scan_count
		FROM scan_jobs 
		WHERE completed_at >= $1 AND completed_at IS NOT NULL
		GROUP BY hour
		ORDER BY hour
	`
	
	startTime := time.Now().Add(-duration)
	rows, err := ds.db.QueryContext(ctx, query, startTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var trends []*TrendDataPoint
	for rows.Next() {
		var timestamp time.Time
		var count int64
		
		if err := rows.Scan(&timestamp, &count); err != nil {
			return nil, err
		}
		
		trends = append(trends, &TrendDataPoint{
			Timestamp: timestamp,
			Value:     float64(count),
			Label:     timestamp.Format("15:04"),
		})
	}
	
	// If no data found, return empty slice instead of mock data
	// This allows the dashboard to handle empty data gracefully
	
	return trends, rows.Err()
}

// GetTopThreats returns top threats based on scan job data
func (ds *DatabaseService) GetTopThreats(limit int) ([]ThreatSummary, error) {
	// Query to get threat distribution from scan jobs
	query := `
		SELECT 
			'critical' as type, 
			SUM(critical_threats) as count,
			'critical' as severity,
			'Critical security threats requiring immediate attention' as description
		FROM scan_jobs 
		WHERE status = 'completed' AND critical_threats > 0
		UNION ALL
		SELECT 
			'high' as type, 
			SUM(high_threats) as count,
			'high' as severity,
			'High-priority security threats' as description
		FROM scan_jobs 
		WHERE status = 'completed' AND high_threats > 0
		UNION ALL
		SELECT 
			'medium' as type, 
			SUM(medium_threats) as count,
			'medium' as severity,
			'Medium-priority security threats' as description
		FROM scan_jobs 
		WHERE status = 'completed' AND medium_threats > 0
		UNION ALL
		SELECT 
			'low' as type, 
			SUM(low_threats) as count,
			'low' as severity,
			'Low-priority security threats' as description
		FROM scan_jobs 
		WHERE status = 'completed' AND low_threats > 0
		ORDER BY count DESC
		LIMIT $1
	`
	
	rows, err := ds.db.QueryContext(context.Background(), query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var threats []ThreatSummary
	for rows.Next() {
		var threat ThreatSummary
		if err := rows.Scan(&threat.Type, &threat.Count, &threat.Severity, &threat.Description); err != nil {
			return nil, err
		}
		threats = append(threats, threat)
	}
	
	// If no data found, return empty slice instead of mock data
	return threats, rows.Err()
}

// GetMitigationStatus returns mitigation status statistics from policy violations
func (ds *DatabaseService) GetMitigationStatus() (map[string]int, error) {
	// Query policy violations to get real mitigation status
	query := `
		SELECT status, COUNT(*) as count
		FROM policy_violations 
		GROUP BY status
	`
	
	rows, err := ds.db.QueryContext(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	status := make(map[string]int)
	for rows.Next() {
		var statusName string
		var count int
		if err := rows.Scan(&statusName, &count); err != nil {
			return nil, err
		}
		status[statusName] = count
	}
	
	// Ensure all expected statuses are present
	if _, exists := status["open"]; !exists {
		status["open"] = 0
	}
	if _, exists := status["in_progress"]; !exists {
		status["in_progress"] = 0
	}
	if _, exists := status["resolved"]; !exists {
		status["resolved"] = 0
	}
	
	return status, rows.Err()
}

// GetSecurityTrends returns security trend data
func (ds *DatabaseService) GetSecurityTrends(days int) ([]TrendDataPoint, error) {
	// Generate security trend data based on threat counts over time
	query := `
		SELECT DATE_TRUNC('day', completed_at) as day, 
		       SUM(total_threats) as threat_count
		FROM scan_jobs 
		WHERE completed_at >= $1 AND completed_at IS NOT NULL
		GROUP BY day
		ORDER BY day
	`
	
	startTime := time.Now().AddDate(0, 0, -days)
	rows, err := ds.db.QueryContext(context.Background(), query, startTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var trends []TrendDataPoint
	for rows.Next() {
		var timestamp time.Time
		var count int64
		
		if err := rows.Scan(&timestamp, &count); err != nil {
			return nil, err
		}
		
		trends = append(trends, TrendDataPoint{
			Timestamp: timestamp,
			Value:     float64(count),
			Label:     timestamp.Format("Jan 02"),
		})
	}
	
	// Return actual data only - no mock data fallback
	
	return trends, nil
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          string    `json:"id"`
	Standard    string    `json:"standard"`
	Rule        string    `json:"rule"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
}

// AuditSummary represents an audit summary
type AuditSummary struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Description string    `json:"description"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	Timestamp   time.Time `json:"timestamp"`
	User        string    `json:"user"`
}

// GetComplianceScore returns the overall compliance score
func (ds *DatabaseService) GetComplianceScore(ctx context.Context) (float64, error) {
	// Mock implementation - return a compliance score between 0 and 100
	return 85.5, nil
}

// GetComplianceByStandard returns compliance data grouped by standard
func (ds *DatabaseService) GetComplianceByStandard(ctx context.Context) (map[string]float64, error) {
	// Mock implementation
	return map[string]float64{
		"SOC2":     90.0,
		"ISO27001": 85.0,
		"PCI-DSS":  88.0,
		"GDPR":     92.0,
	}, nil
}

// GetComplianceViolations returns recent compliance violations
func (ds *DatabaseService) GetComplianceViolations(ctx context.Context, limit int) ([]ComplianceViolation, error) {
	// Mock implementation
	violations := make([]ComplianceViolation, 0, limit)
	for i := 0; i < limit && i < 5; i++ {
		violations = append(violations, ComplianceViolation{
			ID:          fmt.Sprintf("violation-%d", i+1),
			Standard:    "SOC2",
			Rule:        fmt.Sprintf("Rule %d", i+1),
			Severity:    "medium",
			Description: fmt.Sprintf("Compliance violation %d", i+1),
			Resource:    fmt.Sprintf("resource-%d", i+1),
			Status:      "open",
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Hour),
		})
	}
	return violations, nil
}

// GetRecentAudits returns recent audit summaries
func (ds *DatabaseService) GetRecentAudits(ctx context.Context, limit int) ([]AuditSummary, error) {
	// Mock implementation
	audits := make([]AuditSummary, 0, limit)
	for i := 0; i < limit && i < 5; i++ {
		audits = append(audits, AuditSummary{
			ID:          fmt.Sprintf("audit-%d", i+1),
			Type:        "security",
			Status:      "completed",
			Description: fmt.Sprintf("Security audit %d", i+1),
			Action:      "scan",
			Resource:    "repository",
			Timestamp:   time.Now().Add(-time.Duration(i) * 24 * time.Hour),
			User:        "system",
		})
	}
	return audits, nil
}

// GetComplianceTrends returns compliance trend data
func (ds *DatabaseService) GetComplianceTrends(ctx context.Context, days int) ([]TrendDataPoint, error) {
	// Mock implementation
	trends := make([]TrendDataPoint, days)
	for i := 0; i < days; i++ {
		trends[i] = TrendDataPoint{
			Timestamp: time.Now().AddDate(0, 0, -i),
			Value:     80.0 + float64(i%20), // Compliance score between 80-100
			Label:     fmt.Sprintf("Day %d", i+1),
		}
	}
	return trends, nil
}