package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DatabaseSessionManager implements SessionManager using a database
type DatabaseSessionManager struct {
	db     *sql.DB
	config SessionConfig
}

// NewDatabaseSessionManager creates a new database session manager
func NewDatabaseSessionManager(db *sql.DB, config SessionConfig) *DatabaseSessionManager {
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 24 * time.Hour
	}
	if config.RefreshTimeout == 0 {
		config.RefreshTimeout = 7 * 24 * time.Hour
	}

	return &DatabaseSessionManager{
		db:     db,
		config: config,
	}
}

// CreateSession creates a new session for a user
func (sm *DatabaseSessionManager) CreateSession(ctx context.Context, user *User, ipAddress, userAgent string) (*Session, error) {
	// Generate session token
	token, err := sm.generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	session := &Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(sm.config.Timeout),
		CreatedAt: time.Now(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	// Insert session into database
	query := `
		INSERT INTO user_sessions (id, user_id, token, expires_at, created_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = sm.db.ExecContext(ctx, query,
		session.ID,
		session.UserID,
		session.Token,
		session.ExpiresAt,
		session.CreatedAt,
		session.IPAddress,
		session.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// GetSession retrieves a session by token
func (sm *DatabaseSessionManager) GetSession(ctx context.Context, token string) (*Session, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at, ip_address, user_agent
		FROM user_sessions
		WHERE token = $1 AND expires_at > NOW()
	`

	var session Session
	err := sm.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID,
		&session.UserID,
		&session.Token,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.IPAddress,
		&session.UserAgent,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// RefreshSession refreshes a session
func (sm *DatabaseSessionManager) RefreshSession(ctx context.Context, token string) (*Session, error) {
	// Get existing session
	session, err := sm.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}

	// Generate new token
	newToken, err := sm.generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new session token: %w", err)
	}

	// Update session with new token and expiration
	newExpiresAt := time.Now().Add(sm.config.Timeout)
	query := `
		UPDATE user_sessions
		SET token = $1, expires_at = $2
		WHERE id = $3
	`
	_, err = sm.db.ExecContext(ctx, query, newToken, newExpiresAt, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh session: %w", err)
	}

	session.Token = newToken
	session.ExpiresAt = newExpiresAt

	return session, nil
}

// InvalidateSession invalidates a session
func (sm *DatabaseSessionManager) InvalidateSession(ctx context.Context, token string) error {
	query := `DELETE FROM user_sessions WHERE token = $1`
	_, err := sm.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to invalidate session: %w", err)
	}
	return nil
}

// CleanupExpiredSessions removes expired sessions
func (sm *DatabaseSessionManager) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM user_sessions WHERE expires_at <= NOW()`
	result, err := sm.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Printf("Cleaned up %d expired sessions\n", rowsAffected)
	}

	return nil
}

// generateToken generates a secure random token
func (sm *DatabaseSessionManager) generateToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetUserSessions retrieves all active sessions for a user
func (sm *DatabaseSessionManager) GetUserSessions(ctx context.Context, userID string) ([]*Session, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at, ip_address, user_agent
		FROM user_sessions
		WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY created_at DESC
	`

	rows, err := sm.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var session Session
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.Token,
			&session.ExpiresAt,
			&session.CreatedAt,
			&session.IPAddress,
			&session.UserAgent,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, &session)
	}

	return sessions, rows.Err()
}

// InvalidateUserSessions invalidates all sessions for a user
func (sm *DatabaseSessionManager) InvalidateUserSessions(ctx context.Context, userID string) error {
	query := `DELETE FROM user_sessions WHERE user_id = $1`
	result, err := sm.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate user sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Printf("Invalidated %d sessions for user %s\n", rowsAffected, userID)
	}

	return nil
}

// GetSessionStats returns session statistics
func (sm *DatabaseSessionManager) GetSessionStats(ctx context.Context) (*SessionStats, error) {
	query := `
		SELECT 
			COUNT(*) as total_sessions,
			COUNT(CASE WHEN expires_at > NOW() THEN 1 END) as active_sessions,
			COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired_sessions,
			COUNT(DISTINCT user_id) as unique_users
		FROM user_sessions
	`

	var stats SessionStats
	err := sm.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalSessions,
		&stats.ActiveSessions,
		&stats.ExpiredSessions,
		&stats.UniqueUsers,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get session stats: %w", err)
	}

	return &stats, nil
}

// SessionStats represents session statistics
type SessionStats struct {
	TotalSessions   int `json:"total_sessions"`
	ActiveSessions  int `json:"active_sessions"`
	ExpiredSessions int `json:"expired_sessions"`
	UniqueUsers     int `json:"unique_users"`
}

// InitializeSessionTables creates the necessary database tables for sessions
func (sm *DatabaseSessionManager) InitializeSessionTables(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS user_sessions (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL,
			token VARCHAR(64) UNIQUE NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			ip_address VARCHAR(45),
			user_agent TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
	`

	_, err := sm.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to initialize session tables: %w", err)
	}

	return nil
}