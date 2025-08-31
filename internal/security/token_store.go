package security

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// TokenStore interface defines methods for token storage and management
type TokenStore interface {
	// StoreRefreshToken stores a refresh token in the database
	StoreRefreshToken(ctx context.Context, token *RefreshTokenInfo) error

	// GetRefreshToken retrieves a refresh token by token ID
	GetRefreshToken(ctx context.Context, tokenID string) (*RefreshTokenInfo, error)

	// ValidateRefreshToken validates a refresh token and returns token info
	ValidateRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenInfo, error)

	// RevokeRefreshToken marks a refresh token as inactive
	RevokeRefreshToken(ctx context.Context, tokenID string, revokedBy string, reason string) error

	// RevokeToken adds a token to the revocation list
	RevokeToken(ctx context.Context, tokenID, tokenType, userID, reason string, expiresAt time.Time) error

	// IsTokenRevoked checks if a token has been revoked
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)

	// UpdateRefreshTokenLastUsed updates the last used timestamp
	UpdateRefreshTokenLastUsed(ctx context.Context, tokenID string) error

	// CleanupExpiredTokens removes expired tokens from the database
	CleanupExpiredTokens(ctx context.Context) error

	// GetActiveRefreshTokensForUser returns active refresh tokens for a user
	GetActiveRefreshTokensForUser(ctx context.Context, userID string) ([]*RefreshTokenInfo, error)

	// RevokeAllUserTokens revokes all tokens for a user
	RevokeAllUserTokens(ctx context.Context, userID, revokedBy, reason string) error

	// RevokeTokensBySession revokes all tokens for a specific session
	RevokeTokensBySession(ctx context.Context, sessionID, revokedBy, reason string) error
}

// RefreshTokenInfo represents refresh token information
type RefreshTokenInfo struct {
	ID         int        `json:"id"`
	TokenID    string     `json:"token_id"`
	TokenHash  string     `json:"token_hash"`
	UserID     string     `json:"user_id"`
	SessionID  string     `json:"session_id"`
	DeviceInfo string     `json:"device_info,omitempty"` // JSON string
	IPAddress  string     `json:"ip_address,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	IsActive   bool       `json:"is_active"`
	LastUsed   *time.Time `json:"last_used,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// RevokedTokenInfo represents revoked token information
type RevokedTokenInfo struct {
	ID        int       `json:"id"`
	TokenID   string    `json:"token_id"`
	TokenType string    `json:"token_type"`
	UserID    string    `json:"user_id,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
	RevokedBy string    `json:"revoked_by,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// DatabaseTokenStore implements TokenStore using PostgreSQL
type DatabaseTokenStore struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewDatabaseTokenStore creates a new database token store
func NewDatabaseTokenStore(db *sql.DB, logger *logger.Logger) *DatabaseTokenStore {
	return &DatabaseTokenStore{
		db:     db,
		logger: logger,
	}
}

// hashToken creates a SHA-256 hash of the token for storage
func (ts *DatabaseTokenStore) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// StoreRefreshToken stores a refresh token in the database
func (ts *DatabaseTokenStore) StoreRefreshToken(ctx context.Context, token *RefreshTokenInfo) error {
	query := `
		INSERT INTO refresh_tokens (
			token_id, token_hash, user_id, session_id, device_info, 
			ip_address, user_agent, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at
	`

	err := ts.db.QueryRowContext(ctx, query,
		token.TokenID,
		token.TokenHash,
		token.UserID,
		token.SessionID,
		token.DeviceInfo,
		token.IPAddress,
		token.UserAgent,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt, &token.UpdatedAt)

	if err != nil {
		ts.logger.Error("Failed to store refresh token", map[string]interface{}{
			"token_id": token.TokenID,
			"user_id":  token.UserID,
			"error":    err.Error(),
		})
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	ts.logger.Debug("Refresh token stored successfully", map[string]interface{}{
		"token_id": token.TokenID,
		"user_id":  token.UserID,
	})

	return nil
}

// InMemoryTokenStore implements TokenStore using in-memory storage for testing
type InMemoryTokenStore struct {
	refreshTokens map[string]*RefreshTokenInfo
	revokedTokens map[string]*RevokedTokenInfo
	mu            sync.RWMutex
}

// NewInMemoryTokenStore creates a new in-memory token store
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		refreshTokens: make(map[string]*RefreshTokenInfo),
		revokedTokens: make(map[string]*RevokedTokenInfo),
	}
}

// StoreRefreshToken stores a refresh token in memory
func (ts *InMemoryTokenStore) StoreRefreshToken(ctx context.Context, token *RefreshTokenInfo) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()
	token.IsActive = true

	ts.refreshTokens[token.TokenID] = token
	return nil
}

// GetRefreshToken retrieves a refresh token by token ID
func (ts *InMemoryTokenStore) GetRefreshToken(ctx context.Context, tokenID string) (*RefreshTokenInfo, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	token, exists := ts.refreshTokens[tokenID]
	if !exists {
		return nil, fmt.Errorf("refresh token not found")
	}

	return token, nil
}

// ValidateRefreshToken validates a refresh token and returns token info
func (ts *InMemoryTokenStore) ValidateRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenInfo, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, token := range ts.refreshTokens {
		if token.TokenHash == tokenHash && token.IsActive && time.Now().Before(token.ExpiresAt) {
			return token, nil
		}
	}

	return nil, fmt.Errorf("invalid or expired refresh token")
}

// RevokeRefreshToken marks a refresh token as inactive
func (ts *InMemoryTokenStore) RevokeRefreshToken(ctx context.Context, tokenID string, revokedBy string, reason string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	token, exists := ts.refreshTokens[tokenID]
	if !exists {
		return fmt.Errorf("refresh token not found")
	}

	token.IsActive = false
	token.UpdatedAt = time.Now()

	// Add to revoked tokens
	revokedToken := &RevokedTokenInfo{
		TokenID:   tokenID,
		TokenType: "refresh",
		UserID:    token.UserID,
		SessionID: token.SessionID,
		RevokedAt: time.Now(),
		RevokedBy: revokedBy,
		Reason:    reason,
		ExpiresAt: token.ExpiresAt,
	}

	ts.revokedTokens[tokenID] = revokedToken
	return nil
}

// RevokeToken adds a token to the revocation list
func (ts *InMemoryTokenStore) RevokeToken(ctx context.Context, tokenID, tokenType, userID, reason string, expiresAt time.Time) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	revokedToken := &RevokedTokenInfo{
		TokenID:   tokenID,
		TokenType: tokenType,
		UserID:    userID,
		RevokedAt: time.Now(),
		Reason:    reason,
		ExpiresAt: expiresAt,
	}

	ts.revokedTokens[tokenID] = revokedToken
	return nil
}

// IsTokenRevoked checks if a token has been revoked
func (ts *InMemoryTokenStore) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	_, exists := ts.revokedTokens[tokenID]
	return exists, nil
}

// UpdateRefreshTokenLastUsed updates the last used timestamp
func (ts *InMemoryTokenStore) UpdateRefreshTokenLastUsed(ctx context.Context, tokenID string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	token, exists := ts.refreshTokens[tokenID]
	if !exists {
		return fmt.Errorf("refresh token not found")
	}

	now := time.Now()
	token.LastUsed = &now
	token.UpdatedAt = now

	return nil
}

// CleanupExpiredTokens removes expired tokens from memory
func (ts *InMemoryTokenStore) CleanupExpiredTokens(ctx context.Context) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()

	// Clean up expired refresh tokens
	for tokenID, token := range ts.refreshTokens {
		if now.After(token.ExpiresAt) {
			delete(ts.refreshTokens, tokenID)
		}
	}

	// Clean up expired revoked tokens
	for tokenID, token := range ts.revokedTokens {
		if now.After(token.ExpiresAt) {
			delete(ts.revokedTokens, tokenID)
		}
	}

	return nil
}

// GetActiveRefreshTokensForUser returns active refresh tokens for a user
func (ts *InMemoryTokenStore) GetActiveRefreshTokensForUser(ctx context.Context, userID string) ([]*RefreshTokenInfo, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var tokens []*RefreshTokenInfo
	for _, token := range ts.refreshTokens {
		if token.UserID == userID && token.IsActive && time.Now().Before(token.ExpiresAt) {
			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (ts *InMemoryTokenStore) RevokeAllUserTokens(ctx context.Context, userID, revokedBy, reason string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for tokenID, token := range ts.refreshTokens {
		if token.UserID == userID && token.IsActive {
			token.IsActive = false
			token.UpdatedAt = time.Now()

			// Add to revoked tokens
			revokedToken := &RevokedTokenInfo{
				TokenID:   tokenID,
				TokenType: "refresh",
				UserID:    userID,
				SessionID: token.SessionID,
				RevokedAt: time.Now(),
				RevokedBy: revokedBy,
				Reason:    reason,
				ExpiresAt: token.ExpiresAt,
			}

			ts.revokedTokens[tokenID] = revokedToken
		}
	}

	return nil
}

// RevokeTokensBySession revokes all tokens for a specific session
func (ts *InMemoryTokenStore) RevokeTokensBySession(ctx context.Context, sessionID, revokedBy, reason string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for tokenID, token := range ts.refreshTokens {
		if token.SessionID == sessionID && token.IsActive {
			token.IsActive = false
			token.UpdatedAt = time.Now()

			// Add to revoked tokens
			revokedToken := &RevokedTokenInfo{
				TokenID:   tokenID,
				TokenType: "refresh",
				UserID:    token.UserID,
				SessionID: sessionID,
				RevokedAt: time.Now(),
				RevokedBy: revokedBy,
				Reason:    reason,
				ExpiresAt: token.ExpiresAt,
			}

			ts.revokedTokens[tokenID] = revokedToken
		}
	}

	return nil
}

// GetRefreshToken retrieves a refresh token by token ID
func (ts *DatabaseTokenStore) GetRefreshToken(ctx context.Context, tokenID string) (*RefreshTokenInfo, error) {
	query := `
		SELECT id, token_id, token_hash, user_id, session_id, device_info,
			   ip_address, user_agent, is_active, last_used, expires_at,
			   created_at, updated_at
		FROM refresh_tokens
		WHERE token_id = $1
	`

	token := &RefreshTokenInfo{}
	var deviceInfo, ipAddress, userAgent sql.NullString
	var lastUsed sql.NullTime

	err := ts.db.QueryRowContext(ctx, query, tokenID).Scan(
		&token.ID,
		&token.TokenID,
		&token.TokenHash,
		&token.UserID,
		&token.SessionID,
		&deviceInfo,
		&ipAddress,
		&userAgent,
		&token.IsActive,
		&lastUsed,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Handle nullable fields
	if deviceInfo.Valid {
		token.DeviceInfo = deviceInfo.String
	}
	if ipAddress.Valid {
		token.IPAddress = ipAddress.String
	}
	if userAgent.Valid {
		token.UserAgent = userAgent.String
	}
	if lastUsed.Valid {
		token.LastUsed = &lastUsed.Time
	}

	return token, nil
}

// ValidateRefreshToken validates a refresh token and returns token info
func (ts *DatabaseTokenStore) ValidateRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenInfo, error) {
	query := `
		SELECT id, token_id, token_hash, user_id, session_id, device_info,
			   ip_address, user_agent, is_active, last_used, expires_at,
			   created_at, updated_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND is_active = true AND expires_at > NOW()
	`

	token := &RefreshTokenInfo{}
	var deviceInfo, ipAddress, userAgent sql.NullString
	var lastUsed sql.NullTime

	err := ts.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.TokenID,
		&token.TokenHash,
		&token.UserID,
		&token.SessionID,
		&deviceInfo,
		&ipAddress,
		&userAgent,
		&token.IsActive,
		&lastUsed,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid or expired refresh token")
		}
		return nil, fmt.Errorf("failed to validate refresh token: %w", err)
	}

	// Handle nullable fields
	if deviceInfo.Valid {
		token.DeviceInfo = deviceInfo.String
	}
	if ipAddress.Valid {
		token.IPAddress = ipAddress.String
	}
	if userAgent.Valid {
		token.UserAgent = userAgent.String
	}
	if lastUsed.Valid {
		token.LastUsed = &lastUsed.Time
	}

	return token, nil
}

// RevokeRefreshToken marks a refresh token as inactive
func (ts *DatabaseTokenStore) RevokeRefreshToken(ctx context.Context, tokenID string, revokedBy string, reason string) error {
	// First, mark the refresh token as inactive
	query := `
		UPDATE refresh_tokens 
		SET is_active = false, updated_at = NOW()
		WHERE token_id = $1
	`

	result, err := ts.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check revocation result: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("refresh token not found")
	}

	// Add to revoked tokens table for audit trail
	return ts.RevokeToken(ctx, tokenID, "refresh", "", reason, time.Now().Add(24*time.Hour))
}

// RevokeToken adds a token to the revocation list
func (ts *DatabaseTokenStore) RevokeToken(ctx context.Context, tokenID, tokenType, userID, reason string, expiresAt time.Time) error {
	query := `
		INSERT INTO revoked_tokens (token_id, token_type, user_id, reason, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (token_id) DO NOTHING
	`

	var userIDPtr *string
	if userID != "" {
		userIDPtr = &userID
	}

	_, err := ts.db.ExecContext(ctx, query, tokenID, tokenType, userIDPtr, reason, expiresAt)
	if err != nil {
		ts.logger.Error("Failed to revoke token", map[string]interface{}{
			"token_id":   tokenID,
			"token_type": tokenType,
			"error":      err.Error(),
		})
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	ts.logger.Info("Token revoked successfully", map[string]interface{}{
		"token_id":   tokenID,
		"token_type": tokenType,
		"reason":     reason,
	})

	return nil
}

// IsTokenRevoked checks if a token has been revoked
func (ts *DatabaseTokenStore) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM revoked_tokens 
			WHERE token_id = $1 AND expires_at > NOW()
		)
	`

	var isRevoked bool
	err := ts.db.QueryRowContext(ctx, query, tokenID).Scan(&isRevoked)
	if err != nil {
		return false, fmt.Errorf("failed to check token revocation: %w", err)
	}

	return isRevoked, nil
}

// UpdateRefreshTokenLastUsed updates the last used timestamp
func (ts *DatabaseTokenStore) UpdateRefreshTokenLastUsed(ctx context.Context, tokenID string) error {
	query := `
		UPDATE refresh_tokens 
		SET last_used = NOW(), updated_at = NOW()
		WHERE token_id = $1 AND is_active = true
	`

	_, err := ts.db.ExecContext(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to update refresh token last used: %w", err)
	}

	return nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (ts *DatabaseTokenStore) CleanupExpiredTokens(ctx context.Context) error {
	// Clean up expired refresh tokens
	refreshQuery := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`
	refreshResult, err := ts.db.ExecContext(ctx, refreshQuery)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired refresh tokens: %w", err)
	}

	refreshDeleted, _ := refreshResult.RowsAffected()

	// Clean up expired revoked tokens
	revokedQuery := `DELETE FROM revoked_tokens WHERE expires_at < NOW()`
	revokedResult, err := ts.db.ExecContext(ctx, revokedQuery)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired revoked tokens: %w", err)
	}

	revokedDeleted, _ := revokedResult.RowsAffected()

	ts.logger.Info("Token cleanup completed", map[string]interface{}{
		"refresh_tokens_deleted": refreshDeleted,
		"revoked_tokens_deleted": revokedDeleted,
	})

	return nil
}

// GetActiveRefreshTokensForUser returns active refresh tokens for a user
func (ts *DatabaseTokenStore) GetActiveRefreshTokensForUser(ctx context.Context, userID string) ([]*RefreshTokenInfo, error) {
	query := `
		SELECT id, token_id, token_hash, user_id, session_id, device_info,
			   ip_address, user_agent, is_active, last_used, expires_at,
			   created_at, updated_at
		FROM refresh_tokens
		WHERE user_id = $1 AND is_active = true AND expires_at > NOW()
		ORDER BY created_at DESC
	`

	rows, err := ts.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active refresh tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*RefreshTokenInfo

	for rows.Next() {
		token := &RefreshTokenInfo{}
		var deviceInfo, ipAddress, userAgent sql.NullString
		var lastUsed sql.NullTime

		err := rows.Scan(
			&token.ID,
			&token.TokenID,
			&token.TokenHash,
			&token.UserID,
			&token.SessionID,
			&deviceInfo,
			&ipAddress,
			&userAgent,
			&token.IsActive,
			&lastUsed,
			&token.ExpiresAt,
			&token.CreatedAt,
			&token.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan refresh token: %w", err)
		}

		// Handle nullable fields
		if deviceInfo.Valid {
			token.DeviceInfo = deviceInfo.String
		}
		if ipAddress.Valid {
			token.IPAddress = ipAddress.String
		}
		if userAgent.Valid {
			token.UserAgent = userAgent.String
		}
		if lastUsed.Valid {
			token.LastUsed = &lastUsed.Time
		}

		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

// RevokeAllUserTokens revokes all tokens for a user
func (ts *DatabaseTokenStore) RevokeAllUserTokens(ctx context.Context, userID, revokedBy, reason string) error {
	// Start a transaction
	tx, err := ts.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Get all active refresh tokens for the user
	query := `
		SELECT token_id FROM refresh_tokens 
		WHERE user_id = $1 AND is_active = true
	`

	rows, err := tx.QueryContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to get user tokens: %w", err)
	}
	defer rows.Close()

	var tokenIDs []string
	for rows.Next() {
		var tokenID string
		if err := rows.Scan(&tokenID); err != nil {
			return fmt.Errorf("failed to scan token ID: %w", err)
		}
		tokenIDs = append(tokenIDs, tokenID)
	}

	// Mark all refresh tokens as inactive
	updateQuery := `
		UPDATE refresh_tokens 
		SET is_active = false, updated_at = NOW()
		WHERE user_id = $1 AND is_active = true
	`

	_, err = tx.ExecContext(ctx, updateQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	// Add all tokens to revoked tokens table
	for _, tokenID := range tokenIDs {
		revokeQuery := `
			INSERT INTO revoked_tokens (token_id, token_type, user_id, revoked_by, reason, expires_at)
			VALUES ($1, 'refresh', $2, $3, $4, $5)
			ON CONFLICT (token_id) DO NOTHING
		`

		var revokedByPtr *string
		if revokedBy != "" {
			revokedByPtr = &revokedBy
		}

		_, err = tx.ExecContext(ctx, revokeQuery, tokenID, userID, revokedByPtr, reason, time.Now().Add(24*time.Hour))
		if err != nil {
			return fmt.Errorf("failed to add token to revocation list: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	ts.logger.Info("All user tokens revoked", map[string]interface{}{
		"user_id":      userID,
		"tokens_count": len(tokenIDs),
		"revoked_by":   revokedBy,
		"reason":       reason,
	})

	return nil
}

// RevokeTokensBySession revokes all tokens for a specific session
func (ts *DatabaseTokenStore) RevokeTokensBySession(ctx context.Context, sessionID, revokedBy, reason string) error {
	// Start a transaction
	tx, err := ts.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Get all active refresh tokens for the session
	query := `
		SELECT token_id, user_id FROM refresh_tokens 
		WHERE session_id = $1 AND is_active = true
	`

	rows, err := tx.QueryContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session tokens: %w", err)
	}
	defer rows.Close()

	var tokenData []struct {
		TokenID string
		UserID  string
	}

	for rows.Next() {
		var data struct {
			TokenID string
			UserID  string
		}
		if err := rows.Scan(&data.TokenID, &data.UserID); err != nil {
			return fmt.Errorf("failed to scan token data: %w", err)
		}
		tokenData = append(tokenData, data)
	}

	// Mark all refresh tokens as inactive
	updateQuery := `
		UPDATE refresh_tokens 
		SET is_active = false, updated_at = NOW()
		WHERE session_id = $1 AND is_active = true
	`

	_, err = tx.ExecContext(ctx, updateQuery, sessionID)
	if err != nil {
		return fmt.Errorf("failed to revoke session tokens: %w", err)
	}

	// Add all tokens to revoked tokens table
	for _, data := range tokenData {
		revokeQuery := `
			INSERT INTO revoked_tokens (token_id, token_type, user_id, session_id, revoked_by, reason, expires_at)
			VALUES ($1, 'refresh', $2, $3, $4, $5, $6)
			ON CONFLICT (token_id) DO NOTHING
		`

		var revokedByPtr *string
		if revokedBy != "" {
			revokedByPtr = &revokedBy
		}

		_, err = tx.ExecContext(ctx, revokeQuery, data.TokenID, data.UserID, sessionID, revokedByPtr, reason, time.Now().Add(24*time.Hour))
		if err != nil {
			return fmt.Errorf("failed to add token to revocation list: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	ts.logger.Info("Session tokens revoked", map[string]interface{}{
		"session_id":   sessionID,
		"tokens_count": len(tokenData),
		"revoked_by":   revokedBy,
		"reason":       reason,
	})

	return nil
}
