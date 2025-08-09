package security

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/google/uuid"
)

// AuthService provides enhanced authentication services
type AuthService struct {
	config         *SecurityConfig
	logger         *logger.Logger
	rbacEngine     *auth.RBACEngine
	sessions       map[string]*Session
	sessionsMu     sync.RWMutex
	passwordPolicy *PasswordPolicy
	userRepository UserRepository
	tokenStore     TokenStore
}

// Session represents a user session
type Session struct {
	ID        string
	UserID    string
	Username  string
	Role      string
	CreatedAt time.Time
	LastUsed  time.Time
	IPAddress string
	UserAgent string
	IsActive  bool
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSymbols   bool
	MaxAge           time.Duration
	HistoryCount     int
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	Success      bool   `json:"success"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	Username     string `json:"username,omitempty"`
	Role         string `json:"role,omitempty"`
	RequiresMFA  bool   `json:"requires_mfa,omitempty"`
	Message      string `json:"message,omitempty"`
}

// PasswordChangeRequest represents a password change request
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// NewAuthService creates a new authentication service
func NewAuthService(config *SecurityConfig, logger *logger.Logger, rbacEngine *auth.RBACEngine, userRepository UserRepository, tokenStore TokenStore) *AuthService {
	as := &AuthService{
		config:         config,
		logger:         logger,
		rbacEngine:     rbacEngine,
		sessions:       make(map[string]*Session),
		userRepository: userRepository,
		tokenStore:     tokenStore,
		passwordPolicy: &PasswordPolicy{
			MinLength:        config.Authentication.PasswordMinLength,
			RequireUppercase: config.Authentication.RequireUppercase,
			RequireLowercase: config.Authentication.RequireLowercase,
			RequireNumbers:   config.Authentication.RequireNumbers,
			RequireSymbols:   config.Authentication.RequireSymbols,
			MaxAge:           config.Authentication.PasswordMaxAge,
			HistoryCount:     config.Authentication.PasswordHistoryCount,
		},
	}

	// Start session cleanup routine
	go as.sessionCleanupRoutine()

	return as
}

// Authenticate performs user authentication with enhanced security
func (as *AuthService) Authenticate(ctx context.Context, req *AuthRequest, clientIP, userAgent string) (*AuthResponse, error) {
	// Input validation
	if err := as.validateAuthRequest(req); err != nil {
		as.logger.Warn("Authentication failed - invalid request", map[string]interface{}{
			"username": req.Username,
			"ip":       clientIP,
			"error":    err.Error(),
		})
		return &AuthResponse{
			Success: false,
			Message: "Invalid authentication request",
		}, err
	}

	// Normalize username
	username := strings.ToLower(strings.TrimSpace(req.Username))

	// Get user from RBAC engine (assuming it has user management)
	user, err := as.getUserByUsername(ctx, username)
	if err != nil {
		as.logger.Warn("Authentication failed - user not found", map[string]interface{}{
			"username": username,
			"ip":       clientIP,
		})
		return &AuthResponse{
			Success: false,
			Message: "Invalid credentials",
		}, fmt.Errorf("user not found")
	}

	// Verify password
	if !as.verifyPassword(req.Password, user.PasswordHash) {
		as.logger.Warn("Authentication failed - invalid password", map[string]interface{}{
			"username": username,
			"user_id":  user.ID,
			"ip":       clientIP,
		})
		return &AuthResponse{
			Success: false,
			Message: "Invalid credentials",
		}, fmt.Errorf("invalid password")
	}

	// Check if account is locked or disabled
	if !user.IsActive {
		as.logger.Warn("Authentication failed - account disabled", map[string]interface{}{
			"username": username,
			"user_id":  user.ID,
			"ip":       clientIP,
		})
		return &AuthResponse{
			Success: false,
			Message: "Account is disabled",
		}, fmt.Errorf("account disabled")
	}

	// Check MFA if enabled
	if user.MFAEnabled && req.MFACode == "" {
		return &AuthResponse{
			Success:     false,
			RequiresMFA: true,
			Message:     "MFA code required",
		}, nil
	}

	if user.MFAEnabled && req.MFACode != "" {
		if !as.verifyMFACode(user.MFASecret, req.MFACode) {
			as.logger.Warn("Authentication failed - invalid MFA code", map[string]interface{}{
				"username": username,
				"user_id":  user.ID,
				"ip":       clientIP,
			})
			return &AuthResponse{
				Success: false,
				Message: "Invalid MFA code",
			}, fmt.Errorf("invalid MFA code")
		}
	}

	// Check password expiration
	if as.isPasswordExpired(user.PasswordChangedAt) {
		as.logger.Info("Password expired", map[string]interface{}{
			"username": username,
			"user_id":  user.ID,
		})
		return &AuthResponse{
			Success: false,
			Message: "Password has expired. Please change your password.",
		}, fmt.Errorf("password expired")
	}

	// Create session
	session := as.createSession(user, clientIP, userAgent)

	// Generate tokens
	token, err := as.generateJWTToken(user, session.ID)
	if err != nil {
		as.logger.Error("Failed to generate JWT token", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return &AuthResponse{
			Success: false,
			Message: "Authentication failed",
		}, err
	}

	refreshToken, err := as.generateRefreshToken(user.ID, session.ID)
	if err != nil {
		as.logger.Error("Failed to generate refresh token", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return &AuthResponse{
			Success: false,
			Message: "Authentication failed",
		}, err
	}

	// Update last login
	as.updateLastLogin(ctx, user.ID, clientIP)

	as.logger.Info("User authenticated successfully", map[string]interface{}{
		"username":   username,
		"user_id":    user.ID,
		"ip":         clientIP,
		"session_id": session.ID,
	})

	return &AuthResponse{
		Success:      true,
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(as.config.JWT.AccessTokenExpiration.Seconds()),
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.PrimaryRole(),
		Message:      "Authentication successful",
	}, nil
}

// ChangePassword changes a user's password with validation
func (as *AuthService) ChangePassword(ctx context.Context, userID string, req *PasswordChangeRequest) error {
	// Get user
	user, err := as.getUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Verify current password
	if !as.verifyPassword(req.CurrentPassword, user.PasswordHash) {
		as.logger.Warn("Password change failed - invalid current password", map[string]interface{}{
			"user_id": userID,
		})
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password
	if req.NewPassword != req.ConfirmPassword {
		return fmt.Errorf("new password and confirmation do not match")
	}

	if err := as.validatePassword(req.NewPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Check password history
	if as.isPasswordInHistory(req.NewPassword, user.PasswordHistory) {
		return fmt.Errorf("password has been used recently. Please choose a different password")
	}

	// Hash new password
	hashedPassword, err := as.hashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := as.updateUserPassword(ctx, userID, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all sessions for this user
	as.invalidateUserSessions(userID)

	as.logger.Info("Password changed successfully", map[string]interface{}{
		"user_id": userID,
	})

	return nil
}

// ValidateSession validates a session
func (as *AuthService) ValidateSession(sessionID string) (*Session, error) {
	as.sessionsMu.RLock()
	session, exists := as.sessions[sessionID]
	as.sessionsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if !session.IsActive {
		return nil, fmt.Errorf("session is inactive")
	}

	// Check session timeout
	if time.Since(session.LastUsed) > as.config.Session.IdleTimeout {
		as.invalidateSession(sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Update last used time
	as.sessionsMu.Lock()
	session.LastUsed = time.Now()
	as.sessionsMu.Unlock()

	return session, nil
}

// InvalidateSession invalidates a session
func (as *AuthService) InvalidateSession(sessionID string) {
	as.invalidateSession(sessionID)
}

// RevokeRefreshToken revokes a specific refresh token
func (as *AuthService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if as.tokenStore == nil {
		return fmt.Errorf("token store not available")
	}

	// Validate refresh token first
	refreshClaims, err := as.ValidateRefreshToken(refreshToken)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	// Revoke the token
	if err := as.tokenStore.RevokeRefreshToken(ctx, refreshClaims.TokenID, "system", "manual_revocation"); err != nil {
		as.logger.Error("Failed to revoke refresh token", map[string]interface{}{
			"token_id": refreshClaims.TokenID,
			"error":    err.Error(),
		})
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	as.logger.Info("Refresh token revoked", map[string]interface{}{
		"token_id": refreshClaims.TokenID,
		"user_id":  refreshClaims.Subject,
	})

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a specific user
func (as *AuthService) RevokeAllUserTokens(ctx context.Context, userID string) error {
	if as.tokenStore == nil {
		return fmt.Errorf("token store not available")
	}

	if err := as.tokenStore.RevokeAllUserTokens(ctx, userID, "system", "user_logout"); err != nil {
		as.logger.Error("Failed to revoke all user tokens", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return fmt.Errorf("failed to revoke user tokens: %w", err)
	}

	as.logger.Info("All user tokens revoked", map[string]interface{}{
		"user_id": userID,
	})

	return nil
}

// GetActiveSessions returns active sessions for a user
func (as *AuthService) GetActiveSessions(userID string) []*Session {
	as.sessionsMu.RLock()
	defer as.sessionsMu.RUnlock()

	var sessions []*Session
	for _, session := range as.sessions {
		if session.UserID == userID && session.IsActive {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// Helper methods

func (as *AuthService) validateAuthRequest(req *AuthRequest) error {
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(req.Username) > 255 {
		return fmt.Errorf("username too long")
	}
	if len(req.Password) > 1000 {
		return fmt.Errorf("password too long")
	}
	return nil
}

func (as *AuthService) validatePassword(password string) error {
	if len(password) < as.passwordPolicy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", as.passwordPolicy.MinLength)
	}

	if as.passwordPolicy.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if as.passwordPolicy.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if as.passwordPolicy.RequireNumbers && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one number")
	}

	if as.passwordPolicy.RequireSymbols && !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

func (as *AuthService) hashPassword(password string) (string, error) {
	if as.config.Encryption.UseArgon2 {
		return as.hashPasswordArgon2(password)
	}
	return as.hashPasswordBcrypt(password)
}

func (as *AuthService) hashPasswordBcrypt(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (as *AuthService) hashPasswordArgon2(password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 1, 4,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func (as *AuthService) verifyPassword(password, hash string) bool {
	if strings.HasPrefix(hash, "$argon2id$") {
		return as.verifyPasswordArgon2(password, hash)
	}
	return as.verifyPasswordBcrypt(password, hash)
}

func (as *AuthService) verifyPasswordBcrypt(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (as *AuthService) verifyPasswordArgon2(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	actualHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	
	return subtle.ConstantTimeCompare(expectedHash, actualHash) == 1
}

func (as *AuthService) createSession(user *User, clientIP, userAgent string) *Session {
	sessionID := as.generateSessionID()
	
	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.PrimaryRole(),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		IPAddress: clientIP,
		UserAgent: userAgent,
		IsActive:  true,
	}

	as.sessionsMu.Lock()
	as.sessions[sessionID] = session
	as.sessionsMu.Unlock()

	return session
}

func (as *AuthService) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (as *AuthService) invalidateSession(sessionID string) {
	as.sessionsMu.Lock()
	if session, exists := as.sessions[sessionID]; exists {
		session.IsActive = false
		// Revoke refresh tokens for this session if token store is available
		if as.tokenStore != nil {
			ctx := context.Background()
			if err := as.tokenStore.RevokeTokensBySession(ctx, sessionID, "system", "session_invalidated"); err != nil {
				as.logger.Warn("Failed to revoke refresh tokens for session", map[string]interface{}{
					"session_id": sessionID,
					"error":      err.Error(),
				})
			}
		}
	}
	as.sessionsMu.Unlock()
}

func (as *AuthService) invalidateUserSessions(userID string) {
	as.sessionsMu.Lock()
	for _, session := range as.sessions {
		if session.UserID == userID {
			session.IsActive = false
			// Revoke refresh tokens for this session if token store is available
			if as.tokenStore != nil {
				ctx := context.Background()
				if err := as.tokenStore.RevokeTokensBySession(ctx, session.ID, "system", "session_invalidated"); err != nil {
					as.logger.Warn("Failed to revoke refresh tokens for session", map[string]interface{}{
						"session_id": session.ID,
						"error":      err.Error(),
					})
				}
			}
		}
	}
	as.sessionsMu.Unlock()
}

func (as *AuthService) isPasswordExpired(passwordChangedAt time.Time) bool {
	if as.passwordPolicy.MaxAge == 0 {
		return false
	}
	return time.Since(passwordChangedAt) > as.passwordPolicy.MaxAge
}

func (as *AuthService) isPasswordInHistory(password string, history []string) bool {
	for _, oldHash := range history {
		if as.verifyPassword(password, oldHash) {
			return true
		}
	}
	return false
}

func (as *AuthService) verifyMFACode(secret, code string) bool {
	// Placeholder for TOTP verification
	// In a real implementation, you would use a library like github.com/pquerna/otp
	return code == "123456" // Simplified for demo
}

func (as *AuthService) sessionCleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		as.sessionsMu.Lock()
		now := time.Now()
		for sessionID, session := range as.sessions {
			if !session.IsActive || now.Sub(session.LastUsed) > as.config.Session.IdleTimeout {
				delete(as.sessions, sessionID)
			}
		}
		as.sessionsMu.Unlock()
	}
}

// User represents a user in the system
type User struct {
	ID                   string     `json:"id"`
	Username             string     `json:"username"`
	Email                string     `json:"email"`
	PasswordHash         string     `json:"-"` // Never serialize password hash
	PasswordChangedAt    time.Time  `json:"password_changed_at"`
	PasswordHistory      []string   `json:"-"` // Never serialize password history
	IsActive             bool       `json:"is_active"`
	IsVerified           bool       `json:"is_verified"`
	MFAEnabled           bool       `json:"mfa_enabled"`
	MFASecret            string     `json:"-"` // Never serialize MFA secret
	Roles                []string   `json:"roles"`
	LastLoginAt          time.Time  `json:"last_login_at"`
	LastLoginIP          string     `json:"last_login_ip"`
	FailedLoginAttempts  int        `json:"failed_login_attempts"`
	LockedUntil          *time.Time `json:"locked_until,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func (u *User) PrimaryRole() string {
	if len(u.Roles) > 0 {
		return u.Roles[0]
	}
	return "user"
}

func (as *AuthService) getUserByUsername(ctx context.Context, username string) (*User, error) {
	return as.userRepository.GetUserByUsername(ctx, username)
}

func (as *AuthService) getUserByID(ctx context.Context, userID string) (*User, error) {
	return as.userRepository.GetUserByID(ctx, userID)
}

func (as *AuthService) updateUserPassword(ctx context.Context, userID, hashedPassword string) error {
	return as.userRepository.UpdateUserPassword(ctx, userID, hashedPassword)
}

func (as *AuthService) updateLastLogin(ctx context.Context, userID, clientIP string) {
	as.userRepository.UpdateLastLogin(ctx, userID, clientIP)
}

// JWTHeader represents the header of a JWT token
type JWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	Subject   string `json:"sub"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	SessionID string `json:"sid"`
	TokenID   string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
}

// RefreshTokenClaims represents the claims in a refresh token
type RefreshTokenClaims struct {
	Subject   string `json:"sub"`
	SessionID string `json:"sid"`
	TokenID   string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Type      string `json:"typ"` // "refresh"
}

func (as *AuthService) generateJWTToken(user *User, sessionID string) (string, error) {
	// Create JWT header
	header := JWTHeader{
		Algorithm: as.config.JWT.Algorithm,
		Type:      "JWT",
	}

	// Create JWT claims
	now := time.Now()
	claims := JWTClaims{
		Subject:   user.ID,
		Name:      user.Username,
		Role:      user.PrimaryRole(),
		SessionID: sessionID,
		TokenID:   uuid.New().String(),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(as.config.JWT.AccessTokenExpiration).Unix(),
		Issuer:    as.config.JWT.Issuer,
		Audience:  as.config.JWT.Audience,
	}

	// Marshal header and claims
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT header: %w", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWT claims: %w", err)
	}

	// Base64 encode header and claims
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Create payload
	payload := headerEncoded + "." + claimsEncoded

	// Generate signature
	signature := as.generateJWTSignature(payload)

	// Combine to create final token
	token := payload + "." + signature

	as.logger.Debug("JWT token generated successfully", map[string]interface{}{
		"user_id":    user.ID,
		"username":   user.Username,
		"session_id": sessionID,
		"token_id":   claims.TokenID,
		"expires_at": time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339),
	})

	return token, nil
}

func (as *AuthService) generateRefreshToken(userID, sessionID string) (string, error) {
	// Create JWT header for refresh token
	header := JWTHeader{
		Algorithm: as.config.JWT.Algorithm,
		Type:      "JWT",
	}

	// Create refresh token claims
	now := time.Now()
	tokenID := uuid.New().String()
	expiresAt := now.Add(as.config.JWT.RefreshTokenExpiration)
	
	claims := RefreshTokenClaims{
		Subject:   userID,
		SessionID: sessionID,
		TokenID:   tokenID,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		Issuer:    as.config.JWT.Issuer,
		Audience:  as.config.JWT.Audience,
		Type:      "refresh",
	}

	// Marshal header and claims
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal refresh token header: %w", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal refresh token claims: %w", err)
	}

	// Base64 encode header and claims
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Create payload
	payload := headerEncoded + "." + claimsEncoded

	// Generate signature
	signature := as.generateJWTSignature(payload)

	// Combine to create final token
	token := payload + "." + signature

	// Store refresh token in database if token store is available
	if as.tokenStore != nil {
		// Hash the token for storage
		hash := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(hash[:])
		
		tokenInfo := &RefreshTokenInfo{
			TokenID:   tokenID,
			TokenHash: tokenHash,
			UserID:    userID,
			SessionID: sessionID,
			IsActive:  true,
			ExpiresAt: expiresAt,
		}
		
		ctx := context.Background()
		if err := as.tokenStore.StoreRefreshToken(ctx, tokenInfo); err != nil {
			as.logger.Error("Failed to store refresh token in database", map[string]interface{}{
				"user_id":  userID,
				"token_id": tokenID,
				"error":    err.Error(),
			})
			// Continue without failing - token is still valid even if not stored
		}
	}

	as.logger.Debug("Refresh token generated successfully", map[string]interface{}{
		"user_id":    userID,
		"session_id": sessionID,
		"token_id":   tokenID,
		"expires_at": expiresAt.Format(time.RFC3339),
	})

	return token, nil
}

// generateJWTSignature generates HMAC-SHA256 signature for JWT payload
func (as *AuthService) generateJWTSignature(payload string) string {
	h := hmac.New(sha256.New, []byte(as.config.JWT.SecretKey))
	h.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// ValidateJWTToken validates a JWT token and returns the claims
func (as *AuthService) ValidateJWTToken(tokenString string) (*JWTClaims, error) {
	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Check algorithm
	if header.Algorithm != as.config.JWT.Algorithm {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Algorithm)
	}

	// Verify signature
	payload := parts[0] + "." + parts[1]
	expectedSignature := as.generateJWTSignature(payload)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Check expiration
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	// Check issuer
	if as.config.JWT.Issuer != "" && claims.Issuer != as.config.JWT.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	// Check audience
	if as.config.JWT.Audience != "" && claims.Audience != as.config.JWT.Audience {
		return nil, fmt.Errorf("invalid audience")
	}

	return &claims, nil
}

// ValidateRefreshToken validates a refresh token and returns the claims
func (as *AuthService) ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Check algorithm
	if header.Algorithm != as.config.JWT.Algorithm {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Algorithm)
	}

	// Verify signature
	payload := parts[0] + "." + parts[1]
	expectedSignature := as.generateJWTSignature(payload)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims RefreshTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Check expiration
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	// Check issuer
	if as.config.JWT.Issuer != "" && claims.Issuer != as.config.JWT.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	// Check audience
	if as.config.JWT.Audience != "" && claims.Audience != as.config.JWT.Audience {
		return nil, fmt.Errorf("invalid audience")
	}

	// Check token type
	if claims.Type != "refresh" {
		return nil, fmt.Errorf("invalid token type")
	}

	return &claims, nil
}

// RefreshAccessToken generates a new access token using a valid refresh token
func (as *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// Validate refresh token
	refreshClaims, err := as.ValidateRefreshToken(refreshToken)
	if err != nil {
		as.logger.Warn("Refresh token validation failed", map[string]interface{}{
			"error": err.Error(),
		})
		return &AuthResponse{
			Success: false,
			Message: "Invalid refresh token",
		}, err
	}

	// Check if token is revoked (if token store is available)
	if as.tokenStore != nil {
		isRevoked, err := as.tokenStore.IsTokenRevoked(ctx, refreshClaims.TokenID)
		if err != nil {
			as.logger.Error("Failed to check token revocation", map[string]interface{}{
				"token_id": refreshClaims.TokenID,
				"error":    err.Error(),
			})
		} else if isRevoked {
			as.logger.Warn("Refresh token is revoked", map[string]interface{}{
				"token_id": refreshClaims.TokenID,
				"user_id":  refreshClaims.Subject,
			})
			return &AuthResponse{
				Success: false,
				Message: "Token has been revoked",
			}, fmt.Errorf("token revoked")
		}

		// Validate refresh token in database
		hash := sha256.Sum256([]byte(refreshToken))
		tokenHash := hex.EncodeToString(hash[:])
		
		_, err = as.tokenStore.ValidateRefreshToken(ctx, tokenHash)
		if err != nil {
			as.logger.Warn("Refresh token not found in database", map[string]interface{}{
				"token_id": refreshClaims.TokenID,
				"error":    err.Error(),
			})
			return &AuthResponse{
				Success: false,
				Message: "Invalid refresh token",
			}, err
		}

		// Update last used timestamp
		if err := as.tokenStore.UpdateRefreshTokenLastUsed(ctx, refreshClaims.TokenID); err != nil {
			as.logger.Warn("Failed to update refresh token last used", map[string]interface{}{
				"token_id": refreshClaims.TokenID,
				"error":    err.Error(),
			})
		}
	}

	// Get user by ID
	user, err := as.getUserByID(ctx, refreshClaims.Subject)
	if err != nil {
		as.logger.Warn("User not found during token refresh", map[string]interface{}{
			"user_id": refreshClaims.Subject,
		})
		return &AuthResponse{
			Success: false,
			Message: "User not found",
		}, err
	}

	// Check if user is still active
	if !user.IsActive {
		as.logger.Warn("Token refresh failed - user inactive", map[string]interface{}{
			"user_id": user.ID,
		})
		return &AuthResponse{
			Success: false,
			Message: "Account is disabled",
		}, fmt.Errorf("account disabled")
	}

	// Generate new access token
	newAccessToken, err := as.generateJWTToken(user, refreshClaims.SessionID)
	if err != nil {
		as.logger.Error("Failed to generate new access token", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return &AuthResponse{
			Success: false,
			Message: "Failed to generate token",
		}, err
	}

	as.logger.Info("Access token refreshed successfully", map[string]interface{}{
		"user_id":    user.ID,
		"username":   user.Username,
		"session_id": refreshClaims.SessionID,
	})

	return &AuthResponse{
		Success:   true,
		Token:     newAccessToken,
		ExpiresIn: int64(as.config.JWT.AccessTokenExpiration.Seconds()),
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.PrimaryRole(),
		Message:   "Token refreshed successfully",
	}, nil
}