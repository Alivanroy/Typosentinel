package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	UpdateUserPassword(ctx context.Context, userID, hashedPassword string) error
	UpdateLastLogin(ctx context.Context, userID, clientIP string) error
	IncrementFailedLoginAttempts(ctx context.Context, userID string) error
	ResetFailedLoginAttempts(ctx context.Context, userID string) error
	LockUser(ctx context.Context, userID string, lockDuration time.Duration) error
	UnlockUser(ctx context.Context, userID string) error
	DeleteUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
	AssignRole(ctx context.Context, userID, roleName, assignedBy string) error
	RemoveRole(ctx context.Context, userID, roleName string) error
	LogSecurityEvent(ctx context.Context, event *AuditEvent) error
}

// PostgreSQLUserRepository implements UserRepository for PostgreSQL
type PostgreSQLUserRepository struct {
	db *sql.DB
}

// NewPostgreSQLUserRepository creates a new PostgreSQL user repository
func NewPostgreSQLUserRepository(db *sql.DB) *PostgreSQLUserRepository {
	return &PostgreSQLUserRepository{
		db: db,
	}
}

// AuditEvent represents a security audit event for the database
type AuditEvent struct {
	UserID    *string                `json:"user_id,omitempty"`
	EventType string                 `json:"event_type"`
	EventData map[string]interface{} `json:"event_data,omitempty"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Success   bool                   `json:"success"`
	CreatedAt time.Time              `json:"created_at"`
}

// GetUserByUsername retrieves a user by username
func (r *PostgreSQLUserRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, password_changed_at, password_history,
		       is_active, is_verified, mfa_enabled, mfa_secret, roles, last_login_at, 
		       last_login_ip, failed_login_attempts, locked_until, created_at, updated_at
		FROM users 
		WHERE username = $1
	`

	user := &User{}
	var passwordHistory, roles []byte
	var lastLoginAt, lockedUntil sql.NullTime
	var lastLoginIP sql.NullString
	var mfaSecret sql.NullString

	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.PasswordChangedAt,
		&passwordHistory, &user.IsActive, &user.IsVerified, &user.MFAEnabled, &mfaSecret,
		&roles, &lastLoginAt, &lastLoginIP, &user.FailedLoginAttempts, &lockedUntil,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse JSON fields
	if err := json.Unmarshal(passwordHistory, &user.PasswordHistory); err != nil {
		return nil, fmt.Errorf("failed to parse password history: %w", err)
	}

	if err := json.Unmarshal(roles, &user.Roles); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}

	// Handle nullable fields
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (r *PostgreSQLUserRepository) GetUserByID(ctx context.Context, userID string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, password_changed_at, password_history,
		       is_active, is_verified, mfa_enabled, mfa_secret, roles, last_login_at, 
		       last_login_ip, failed_login_attempts, locked_until, created_at, updated_at
		FROM users 
		WHERE id = $1
	`

	user := &User{}
	var passwordHistory, roles []byte
	var lastLoginAt, lockedUntil sql.NullTime
	var lastLoginIP sql.NullString
	var mfaSecret sql.NullString

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.PasswordChangedAt,
		&passwordHistory, &user.IsActive, &user.IsVerified, &user.MFAEnabled, &mfaSecret,
		&roles, &lastLoginAt, &lastLoginIP, &user.FailedLoginAttempts, &lockedUntil,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse JSON fields
	if err := json.Unmarshal(passwordHistory, &user.PasswordHistory); err != nil {
		return nil, fmt.Errorf("failed to parse password history: %w", err)
	}

	if err := json.Unmarshal(roles, &user.Roles); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}

	// Handle nullable fields
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}

	return user, nil
}

// GetUserByEmail retrieves a user by email
func (r *PostgreSQLUserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, password_changed_at, password_history,
		       is_active, is_verified, mfa_enabled, mfa_secret, roles, last_login_at, 
		       last_login_ip, failed_login_attempts, locked_until, created_at, updated_at
		FROM users 
		WHERE email = $1
	`

	user := &User{}
	var passwordHistory, roles []byte
	var lastLoginAt, lockedUntil sql.NullTime
	var lastLoginIP sql.NullString
	var mfaSecret sql.NullString

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.PasswordChangedAt,
		&passwordHistory, &user.IsActive, &user.IsVerified, &user.MFAEnabled, &mfaSecret,
		&roles, &lastLoginAt, &lastLoginIP, &user.FailedLoginAttempts, &lockedUntil,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse JSON fields
	if err := json.Unmarshal(passwordHistory, &user.PasswordHistory); err != nil {
		return nil, fmt.Errorf("failed to parse password history: %w", err)
	}

	if err := json.Unmarshal(roles, &user.Roles); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %w", err)
	}

	// Handle nullable fields
	if lastLoginAt.Valid {
		user.LastLoginAt = lastLoginAt.Time
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}

	return user, nil
}

// CreateUser creates a new user
func (r *PostgreSQLUserRepository) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	passwordHistoryJSON, err := json.Marshal(user.PasswordHistory)
	if err != nil {
		return fmt.Errorf("failed to marshal password history: %w", err)
	}

	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		INSERT INTO users (
			id, username, email, password_hash, password_changed_at, password_history,
			is_active, is_verified, mfa_enabled, mfa_secret, roles, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
	`

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err = r.db.ExecContext(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash, user.PasswordChangedAt,
		passwordHistoryJSON, user.IsActive, user.IsVerified, user.MFAEnabled, user.MFASecret,
		rolesJSON, user.CreatedAt, user.UpdatedAt,
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23505": // unique_violation
				if pqErr.Constraint == "users_username_key" {
					return fmt.Errorf("username already exists")
				}
				if pqErr.Constraint == "users_email_key" {
					return fmt.Errorf("email already exists")
				}
			}
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// UpdateUser updates an existing user
func (r *PostgreSQLUserRepository) UpdateUser(ctx context.Context, user *User) error {
	passwordHistoryJSON, err := json.Marshal(user.PasswordHistory)
	if err != nil {
		return fmt.Errorf("failed to marshal password history: %w", err)
	}

	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	query := `
		UPDATE users SET
			username = $2, email = $3, password_hash = $4, password_changed_at = $5,
			password_history = $6, is_active = $7, is_verified = $8, mfa_enabled = $9,
			mfa_secret = $10, roles = $11, last_login_at = $12, last_login_ip = $13,
			failed_login_attempts = $14, locked_until = $15, updated_at = $16
		WHERE id = $1
	`

	user.UpdatedAt = time.Now()

	result, err := r.db.ExecContext(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash, user.PasswordChangedAt,
		passwordHistoryJSON, user.IsActive, user.IsVerified, user.MFAEnabled, user.MFASecret,
		rolesJSON, user.LastLoginAt, user.LastLoginIP, user.FailedLoginAttempts,
		user.LockedUntil, user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdateUserPassword updates a user's password and adds the old one to history
func (r *PostgreSQLUserRepository) UpdateUserPassword(ctx context.Context, userID, hashedPassword string) error {
	// Get current user to update password history
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Add current password to history
	user.PasswordHistory = append(user.PasswordHistory, user.PasswordHash)

	// Keep only last 10 passwords in history
	if len(user.PasswordHistory) > 10 {
		user.PasswordHistory = user.PasswordHistory[len(user.PasswordHistory)-10:]
	}

	passwordHistoryJSON, err := json.Marshal(user.PasswordHistory)
	if err != nil {
		return fmt.Errorf("failed to marshal password history: %w", err)
	}

	query := `
		UPDATE users SET
			password_hash = $2, password_changed_at = $3, password_history = $4, updated_at = $5
		WHERE id = $1
	`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query, userID, hashedPassword, now, passwordHistoryJSON, now)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdateLastLogin updates the user's last login information
func (r *PostgreSQLUserRepository) UpdateLastLogin(ctx context.Context, userID, clientIP string) error {
	query := `
		UPDATE users SET
			last_login_at = $2, last_login_ip = $3, updated_at = $4
		WHERE id = $1
	`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, userID, now, clientIP, now)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// IncrementFailedLoginAttempts increments the failed login attempts counter
func (r *PostgreSQLUserRepository) IncrementFailedLoginAttempts(ctx context.Context, userID string) error {
	query := `
		UPDATE users SET
			failed_login_attempts = failed_login_attempts + 1, updated_at = $2
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to increment failed login attempts: %w", err)
	}

	return nil
}

// ResetFailedLoginAttempts resets the failed login attempts counter
func (r *PostgreSQLUserRepository) ResetFailedLoginAttempts(ctx context.Context, userID string) error {
	query := `
		UPDATE users SET
			failed_login_attempts = 0, locked_until = NULL, updated_at = $2
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}

	return nil
}

// LockUser locks a user account for a specified duration
func (r *PostgreSQLUserRepository) LockUser(ctx context.Context, userID string, lockDuration time.Duration) error {
	lockUntil := time.Now().Add(lockDuration)

	query := `
		UPDATE users SET
			locked_until = $2, updated_at = $3
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, userID, lockUntil, time.Now())
	if err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}

	return nil
}

// UnlockUser unlocks a user account
func (r *PostgreSQLUserRepository) UnlockUser(ctx context.Context, userID string) error {
	query := `
		UPDATE users SET
			locked_until = NULL, failed_login_attempts = 0, updated_at = $2
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	return nil
}

// DeleteUser deletes a user (soft delete by setting is_active to false)
func (r *PostgreSQLUserRepository) DeleteUser(ctx context.Context, userID string) error {
	query := `
		UPDATE users SET
			is_active = false, updated_at = $2
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, userID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ListUsers returns a paginated list of users
func (r *PostgreSQLUserRepository) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	query := `
		SELECT id, username, email, password_hash, password_changed_at, password_history,
		       is_active, is_verified, mfa_enabled, mfa_secret, roles, last_login_at, 
		       last_login_ip, failed_login_attempts, locked_until, created_at, updated_at
		FROM users 
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		var passwordHistory, roles []byte
		var lastLoginAt, lockedUntil sql.NullTime
		var lastLoginIP sql.NullString
		var mfaSecret sql.NullString

		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.PasswordChangedAt,
			&passwordHistory, &user.IsActive, &user.IsVerified, &user.MFAEnabled, &mfaSecret,
			&roles, &lastLoginAt, &lastLoginIP, &user.FailedLoginAttempts, &lockedUntil,
			&user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		// Parse JSON fields
		if err := json.Unmarshal(passwordHistory, &user.PasswordHistory); err != nil {
			return nil, fmt.Errorf("failed to parse password history: %w", err)
		}

		if err := json.Unmarshal(roles, &user.Roles); err != nil {
			return nil, fmt.Errorf("failed to parse roles: %w", err)
		}

		// Handle nullable fields
		if lastLoginAt.Valid {
			user.LastLoginAt = lastLoginAt.Time
		}
		if lastLoginIP.Valid {
			user.LastLoginIP = lastLoginIP.String
		}
		if mfaSecret.Valid {
			user.MFASecret = mfaSecret.String
		}
		if lockedUntil.Valid {
			user.LockedUntil = &lockedUntil.Time
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate users: %w", err)
	}

	return users, nil
}

// GetUserRoles returns the roles assigned to a user
func (r *PostgreSQLUserRepository) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT role_name
		FROM user_role_assignments
		WHERE user_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate roles: %w", err)
	}

	return roles, nil
}

// AssignRole assigns a role to a user
func (r *PostgreSQLUserRepository) AssignRole(ctx context.Context, userID, roleName, assignedBy string) error {
	query := `
		INSERT INTO user_role_assignments (user_id, role_name, assigned_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_name) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, userID, roleName, assignedBy)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RemoveRole removes a role from a user
func (r *PostgreSQLUserRepository) RemoveRole(ctx context.Context, userID, roleName string) error {
	query := `
		DELETE FROM user_role_assignments
		WHERE user_id = $1 AND role_name = $2
	`

	_, err := r.db.ExecContext(ctx, query, userID, roleName)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	return nil
}

// LogSecurityEvent logs a security event to the audit log
func (r *PostgreSQLUserRepository) LogSecurityEvent(ctx context.Context, event *AuditEvent) error {
	eventDataJSON, err := json.Marshal(event.EventData)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	query := `
		INSERT INTO security_audit_log (user_id, event_type, event_data, ip_address, user_agent, success)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err = r.db.ExecContext(ctx, query,
		event.UserID, event.EventType, eventDataJSON, event.IPAddress, event.UserAgent, event.Success,
	)
	if err != nil {
		return fmt.Errorf("failed to log security event: %w", err)
	}

	return nil
}
