package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// DatabaseService provides CRUD operations for the database
type DatabaseService struct {
	db     *sql.DB
	config *DatabaseConfig
}

// DatabaseConfig contains database connection configuration
type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	SSLMode  string `json:"sslmode"`
	MaxConns int    `json:"max_conns"`
	MaxIdle  int    `json:"max_idle"`
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
func NewDatabaseService(config *DatabaseConfig) (*DatabaseService, error) {
	if config == nil {
		return nil, fmt.Errorf("database config cannot be nil")
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	if config.MaxConns > 0 {
		db.SetMaxOpenConns(config.MaxConns)
	}
	if config.MaxIdle > 0 {
		db.SetMaxIdleConns(config.MaxIdle)
	}
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DatabaseService{
		db:     db,
		config: config,
	}, nil
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