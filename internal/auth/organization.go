package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OrganizationService handles organization management operations
type OrganizationService struct {
	db *sql.DB
}

// NewOrganizationService creates a new organization service
func NewOrganizationService(db *sql.DB) *OrganizationService {
	return &OrganizationService{db: db}
}

// Organization represents an organization in the system
type Organization struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Settings    map[string]interface{} `json:"settings"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// CreateOrganizationRequest represents a request to create a new organization
type CreateOrganizationRequest struct {
	Name        string                 `json:"name" binding:"required,min=2,max=100"`
	Description string                 `json:"description"`
	Settings    map[string]interface{} `json:"settings"`
}

// UpdateOrganizationRequest represents a request to update an organization
type UpdateOrganizationRequest struct {
	Name        *string                 `json:"name,omitempty" binding:"omitempty,min=2,max=100"`
	Description *string                 `json:"description,omitempty"`
	Settings    *map[string]interface{} `json:"settings,omitempty"`
}

// OrganizationSettings represents organization-specific settings
type OrganizationSettings struct {
	// Security settings
	PasswordPolicy PasswordPolicy `json:"password_policy"`
	SessionTimeout int            `json:"session_timeout_minutes"` // in minutes
	MFARequired    bool           `json:"mfa_required"`

	// Scanning settings
	DefaultScanPolicy   string   `json:"default_scan_policy"`
	AllowedRegistries   []string `json:"allowed_registries"`
	BlockedPackages     []string `json:"blocked_packages"`
	ThreatThreshold     string   `json:"threat_threshold"` // low, medium, high, critical
	AutoBlockMalicious  bool     `json:"auto_block_malicious"`
	NotificationWebhook string   `json:"notification_webhook"`

	// Audit settings
	AuditRetentionDays int  `json:"audit_retention_days"`
	DetailedLogging    bool `json:"detailed_logging"`

	// API settings
	RateLimitPerMinute int      `json:"rate_limit_per_minute"`
	AllowedIPRanges    []string `json:"allowed_ip_ranges"`

	// Integration settings
	SlackWebhook    string `json:"slack_webhook"`
	EmailNotify     bool   `json:"email_notifications"`
	JiraIntegration bool   `json:"jira_integration"`
}

// PasswordPolicy represents password requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSymbols   bool `json:"require_symbols"`
	MaxAge           int  `json:"max_age_days"` // 0 means no expiration
}

// GetDefaultSettings returns default organization settings
func GetDefaultSettings() OrganizationSettings {
	return OrganizationSettings{
		PasswordPolicy: PasswordPolicy{
			MinLength:        8,
			RequireUppercase: true,
			RequireLowercase: true,
			RequireNumbers:   true,
			RequireSymbols:   false,
			MaxAge:           90,
		},
		SessionTimeout:      480, // 8 hours
		MFARequired:         false,
		DefaultScanPolicy:   "standard",
		AllowedRegistries:   []string{"npm", "pypi", "go"},
		BlockedPackages:     []string{},
		ThreatThreshold:     "medium",
		AutoBlockMalicious:  true,
		NotificationWebhook: "",
		AuditRetentionDays:  90,
		DetailedLogging:     true,
		RateLimitPerMinute:  1000,
		AllowedIPRanges:     []string{},
		SlackWebhook:        "",
		EmailNotify:         true,
		JiraIntegration:     false,
	}
}

// CreateOrganization creates a new organization
func (s *OrganizationService) CreateOrganization(ctx context.Context, req *CreateOrganizationRequest) (*Organization, error) {
	// Generate organization ID
	orgID := uuid.New()
	now := time.Now()

	// Use default settings if none provided
	settings := req.Settings
	if settings == nil {
		defaultSettings := GetDefaultSettings()
		settings = map[string]interface{}{
			"password_policy":        defaultSettings.PasswordPolicy,
			"session_timeout":       defaultSettings.SessionTimeout,
			"mfa_required":          defaultSettings.MFARequired,
			"default_scan_policy":   defaultSettings.DefaultScanPolicy,
			"allowed_registries":    defaultSettings.AllowedRegistries,
			"blocked_packages":      defaultSettings.BlockedPackages,
			"threat_threshold":      defaultSettings.ThreatThreshold,
			"auto_block_malicious":  defaultSettings.AutoBlockMalicious,
			"notification_webhook":  defaultSettings.NotificationWebhook,
			"audit_retention_days":  defaultSettings.AuditRetentionDays,
			"detailed_logging":      defaultSettings.DetailedLogging,
			"rate_limit_per_minute": defaultSettings.RateLimitPerMinute,
			"allowed_ip_ranges":     defaultSettings.AllowedIPRanges,
			"slack_webhook":         defaultSettings.SlackWebhook,
			"email_notifications":   defaultSettings.EmailNotify,
			"jira_integration":      defaultSettings.JiraIntegration,
		}
	}

	// Convert settings to JSON
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}

	// Insert organization into database
	query := `
		INSERT INTO organizations (id, name, description, settings, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, description, settings, created_at, updated_at
	`

	var org Organization
	var settingsStr string

	err = s.db.QueryRowContext(ctx, query,
		orgID, req.Name, req.Description, settingsJSON, now, now,
	).Scan(
		&org.ID, &org.Name, &org.Description, &settingsStr,
		&org.CreatedAt, &org.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// Parse settings back
	if err := json.Unmarshal([]byte(settingsStr), &org.Settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return &org, nil
}

// GetOrganization retrieves an organization by ID
func (s *OrganizationService) GetOrganization(ctx context.Context, orgID uuid.UUID) (*Organization, error) {
	query := `
		SELECT id, name, description, settings, created_at, updated_at
		FROM organizations
		WHERE id = $1
	`

	var org Organization
	var settingsStr string

	err := s.db.QueryRowContext(ctx, query, orgID).Scan(
		&org.ID, &org.Name, &org.Description, &settingsStr,
		&org.CreatedAt, &org.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	// Parse settings
	if err := json.Unmarshal([]byte(settingsStr), &org.Settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return &org, nil
}

// UpdateOrganization updates an organization
func (s *OrganizationService) UpdateOrganization(ctx context.Context, orgID uuid.UUID, req *UpdateOrganizationRequest) (*Organization, error) {
	// Build dynamic update query
	setClauses := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIndex := 1

	if req.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIndex))
		args = append(args, *req.Name)
		argIndex++
	}

	if req.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *req.Description)
		argIndex++
	}

	if req.Settings != nil {
		settingsJSON, err := json.Marshal(*req.Settings)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal settings: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("settings = $%d", argIndex))
		args = append(args, settingsJSON)
		argIndex++
	}

	args = append(args, orgID)
	query := fmt.Sprintf(`
		UPDATE organizations
		SET %s
		WHERE id = $%d
		RETURNING id, name, description, settings, created_at, updated_at
	`, fmt.Sprintf("%s", setClauses), argIndex)

	var org Organization
	var settingsStr string

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&org.ID, &org.Name, &org.Description, &settingsStr,
		&org.CreatedAt, &org.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("organization not found")
		}
		return nil, fmt.Errorf("failed to update organization: %w", err)
	}

	// Parse settings
	if err := json.Unmarshal([]byte(settingsStr), &org.Settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return &org, nil
}

// DeleteOrganization deletes an organization (hard delete)
func (s *OrganizationService) DeleteOrganization(ctx context.Context, orgID uuid.UUID) error {
	// Start transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete users first (due to foreign key constraint)
	_, err = tx.ExecContext(ctx, "DELETE FROM users WHERE organization_id = $1", orgID)
	if err != nil {
		return fmt.Errorf("failed to delete users: %w", err)
	}

	// Delete API keys
	_, err = tx.ExecContext(ctx, "DELETE FROM api_keys WHERE organization_id = $1", orgID)
	if err != nil {
		return fmt.Errorf("failed to delete API keys: %w", err)
	}

	// Delete organization
	result, err := tx.ExecContext(ctx, "DELETE FROM organizations WHERE id = $1", orgID)
	if err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("organization not found")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListOrganizations lists all organizations with pagination
func (s *OrganizationService) ListOrganizations(ctx context.Context, limit, offset int) ([]*Organization, int, error) {
	// Get total count
	countQuery := `SELECT COUNT(*) FROM organizations`
	var total int
	err := s.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get organization count: %w", err)
	}

	// Get organizations
	query := `
		SELECT id, name, description, settings, created_at, updated_at
		FROM organizations
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var organizations []*Organization
	for rows.Next() {
		var org Organization
		var settingsStr string

		err := rows.Scan(
			&org.ID, &org.Name, &org.Description, &settingsStr,
			&org.CreatedAt, &org.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan organization: %w", err)
		}

		// Parse settings
		if err := json.Unmarshal([]byte(settingsStr), &org.Settings); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal settings: %w", err)
		}

		organizations = append(organizations, &org)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate organizations: %w", err)
	}

	return organizations, total, nil
}

// GetOrganizationStats returns statistics for an organization
func (s *OrganizationService) GetOrganizationStats(ctx context.Context, orgID uuid.UUID) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get user count
	var userCount int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE organization_id = $1 AND is_active = true", orgID).Scan(&userCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get user count: %w", err)
	}
	stats["user_count"] = userCount

	// Get API key count
	var apiKeyCount int
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_keys WHERE organization_id = $1 AND is_active = true", orgID).Scan(&apiKeyCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get API key count: %w", err)
	}
	stats["api_key_count"] = apiKeyCount

	// Get scan count (last 30 days)
	var scanCount int
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM scan_requests 
		WHERE organization_id = $1 AND created_at > NOW() - INTERVAL '30 days'
	`, orgID).Scan(&scanCount)
	if err != nil {
		// If scan_requests table doesn't exist yet, set to 0
		scanCount = 0
	}
	stats["scan_count_30d"] = scanCount

	// Get threat count (last 30 days)
	var threatCount int
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM threats 
		WHERE organization_id = $1 AND detected_at > NOW() - INTERVAL '30 days'
	`, orgID).Scan(&threatCount)
	if err != nil {
		// If threats table doesn't exist yet, set to 0
		threatCount = 0
	}
	stats["threat_count_30d"] = threatCount

	return stats, nil
}