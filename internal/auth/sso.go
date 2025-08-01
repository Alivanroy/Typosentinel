package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// SSOProvider defines the interface for SSO authentication providers
type SSOProvider interface {
	GetAuthURL(state string) (string, error)
	ExchangeCode(code, state string) (*SSOToken, error)
	GetUserInfo(token *SSOToken) (*SSOUser, error)
	ValidateToken(token string) (*SSOUser, error)
	RefreshToken(refreshToken string) (*SSOToken, error)
	Logout(token string) error
	GetProviderName() string
}

// SSOToken represents an SSO authentication token
type SSOToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
}

// SSOUser represents a user from SSO provider
type SSOUser struct {
	ID          string            `json:"id"`
	Email       string            `json:"email"`
	Name        string            `json:"name"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	Username    string            `json:"username,omitempty"`
	Picture     string            `json:"picture,omitempty"`
	Provider    string            `json:"provider"`
	Roles       []string          `json:"roles,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Verified    bool              `json:"verified"`
	LastLoginAt time.Time         `json:"last_login_at"`
}

// SSOManager manages multiple SSO providers
type SSOManager struct {
	providers map[string]SSOProvider
	sessions  map[string]*SSOSession
	config    *SSOConfig
	logger    *logrus.Logger
}

// SSOSession represents an active SSO session
type SSOSession struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Provider    string    `json:"provider"`
	Token       *SSOToken `json:"token"`
	User        *SSOUser  `json:"user"`
	CreatedAt   time.Time `json:"created_at"`
	LastAccess  time.Time `json:"last_access"`
	ExpiresAt   time.Time `json:"expires_at"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

// SSOConfig contains SSO configuration
type SSOConfig struct {
	Enabled   bool                      `json:"enabled" yaml:"enabled"`
	Providers map[string]ProviderConfig `json:"providers" yaml:"providers"`
	Session   SSOSessionConfig          `json:"session" yaml:"session"`
	Security  SSOSecurityConfig         `json:"security" yaml:"security"`
}

// SSOSessionConfig configures SSO sessions
type SSOSessionConfig struct {
	Timeout        time.Duration `json:"timeout" yaml:"timeout"`
	RefreshWindow  time.Duration `json:"refresh_window" yaml:"refresh_window"`
	CleanupInterval time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	SecureCookies  bool          `json:"secure_cookies" yaml:"secure_cookies"`
	SameSite       string        `json:"same_site" yaml:"same_site"`
}

// SSOSecurityConfig configures SSO security settings
type SSOSecurityConfig struct {
	StateTimeout    time.Duration `json:"state_timeout" yaml:"state_timeout"`
	CSRFProtection  bool          `json:"csrf_protection" yaml:"csrf_protection"`
	AllowedDomains  []string      `json:"allowed_domains" yaml:"allowed_domains"`
	RequireHTTPS    bool          `json:"require_https" yaml:"require_https"`
	TrustedProxies  []string      `json:"trusted_proxies" yaml:"trusted_proxies"`
}

// NewSSOManager creates a new SSO manager
func NewSSOManager(config *SSOConfig, logger *logrus.Logger) *SSOManager {
	if logger == nil {
		logger = logrus.New()
	}

	return &SSOManager{
		providers: make(map[string]SSOProvider),
		sessions:  make(map[string]*SSOSession),
		config:    config,
		logger:    logger,
	}
}

// RegisterProvider registers an SSO provider
func (sm *SSOManager) RegisterProvider(name string, provider SSOProvider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	sm.providers[name] = provider
	sm.logger.Infof("Registered SSO provider: %s", name)
	return nil
}

// GetProvider returns an SSO provider by name
func (sm *SSOManager) GetProvider(name string) (SSOProvider, error) {
	provider, exists := sm.providers[name]
	if !exists {
		return nil, fmt.Errorf("SSO provider not found: %s", name)
	}
	return provider, nil
}

// GetAuthURL generates an authentication URL for the specified provider
func (sm *SSOManager) GetAuthURL(providerName string) (string, string, error) {
	provider, err := sm.GetProvider(providerName)
	if err != nil {
		return "", "", err
	}

	// Generate secure state parameter
	state, err := sm.generateState()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state: %w", err)
	}

	authURL, err := provider.GetAuthURL(state)
	if err != nil {
		return "", "", fmt.Errorf("failed to get auth URL: %w", err)
	}

	return authURL, state, nil
}

// HandleCallback handles the SSO callback
func (sm *SSOManager) HandleCallback(providerName, code, state string, r *http.Request) (*SSOSession, error) {
	provider, err := sm.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Validate state parameter
	if !sm.validateState(state) {
		return nil, fmt.Errorf("invalid state parameter")
	}

	// Exchange code for token
	token, err := provider.ExchangeCode(code, state)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user information
	user, err := provider.GetUserInfo(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Validate user domain if configured
	if err := sm.validateUserDomain(user.Email); err != nil {
		return nil, err
	}

	// Create session
	session := &SSOSession{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Provider:   providerName,
		Token:      token,
		User:       user,
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(sm.config.Session.Timeout),
		IPAddress:  sm.getClientIP(r),
		UserAgent:  r.UserAgent(),
	}

	sm.sessions[session.ID] = session
	sm.logger.Infof("Created SSO session for user %s via %s", user.Email, providerName)

	return session, nil
}

// ValidateSession validates an SSO session
func (sm *SSOManager) ValidateSession(sessionID string) (*SSOSession, error) {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		delete(sm.sessions, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Update last access time
	session.LastAccess = time.Now()

	// Check if token needs refresh
	if sm.shouldRefreshToken(session.Token) {
		if err := sm.refreshSessionToken(session); err != nil {
			sm.logger.Warnf("Failed to refresh token for session %s: %v", sessionID, err)
		}
	}

	return session, nil
}

// RefreshSession refreshes an SSO session token
func (sm *SSOManager) RefreshSession(sessionID string) error {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	return sm.refreshSessionToken(session)
}

// LogoutSession logs out an SSO session
func (sm *SSOManager) LogoutSession(sessionID string) error {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	// Logout from provider
	provider, err := sm.GetProvider(session.Provider)
	if err == nil {
		if err := provider.Logout(session.Token.AccessToken); err != nil {
			sm.logger.Warnf("Failed to logout from provider %s: %v", session.Provider, err)
		}
	}

	// Remove session
	delete(sm.sessions, sessionID)
	sm.logger.Infof("Logged out SSO session %s for user %s", sessionID, session.User.Email)

	return nil
}

// GetUserFromSession returns user information from session
func (sm *SSOManager) GetUserFromSession(sessionID string) (*SSOUser, error) {
	session, err := sm.ValidateSession(sessionID)
	if err != nil {
		return nil, err
	}
	return session.User, nil
}

// ListActiveSessions returns all active sessions
func (sm *SSOManager) ListActiveSessions() []*SSOSession {
	var sessions []*SSOSession
	for _, session := range sm.sessions {
		if time.Now().Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// CleanupExpiredSessions removes expired sessions
func (sm *SSOManager) CleanupExpiredSessions() {
	now := time.Now()
	var expiredSessions []string

	for sessionID, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		delete(sm.sessions, sessionID)
	}

	if len(expiredSessions) > 0 {
		sm.logger.Infof("Cleaned up %d expired SSO sessions", len(expiredSessions))
	}
}

// StartCleanupRoutine starts a background routine to clean up expired sessions
func (sm *SSOManager) StartCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(sm.config.Session.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.CleanupExpiredSessions()
		}
	}
}

// generateState generates a secure state parameter
func (sm *SSOManager) generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// validateState validates a state parameter
func (sm *SSOManager) validateState(state string) bool {
	// Basic validation - in production, you'd want to store and validate states
	if len(state) < 32 {
		return false
	}
	_, err := base64.URLEncoding.DecodeString(state)
	return err == nil
}

// validateUserDomain validates user email domain against allowed domains
func (sm *SSOManager) validateUserDomain(email string) error {
	if len(sm.config.Security.AllowedDomains) == 0 {
		return nil // No domain restrictions
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format")
	}

	domain := strings.ToLower(parts[1])
	for _, allowedDomain := range sm.config.Security.AllowedDomains {
		if strings.ToLower(allowedDomain) == domain {
			return nil
		}
	}

	return fmt.Errorf("email domain %s is not allowed", domain)
}

// shouldRefreshToken checks if a token should be refreshed
func (sm *SSOManager) shouldRefreshToken(token *SSOToken) bool {
	if token.RefreshToken == "" {
		return false
	}

	// Refresh if token expires within the refresh window
	refreshTime := token.ExpiresAt.Add(-sm.config.Session.RefreshWindow)
	return time.Now().After(refreshTime)
}

// refreshSessionToken refreshes a session's token
func (sm *SSOManager) refreshSessionToken(session *SSOSession) error {
	provider, err := sm.GetProvider(session.Provider)
	if err != nil {
		return err
	}

	newToken, err := provider.RefreshToken(session.Token.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	session.Token = newToken
	sm.logger.Infof("Refreshed token for session %s", session.ID)

	return nil
}

// getClientIP extracts client IP from request
func (sm *SSOManager) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}

	return "unknown"
}

// GetSessionStats returns statistics about active sessions
func (sm *SSOManager) GetSessionStats() map[string]interface{} {
	stats := make(map[string]interface{})
	providerCounts := make(map[string]int)
	totalSessions := 0
	activeSessions := 0

	now := time.Now()
	for _, session := range sm.sessions {
		totalSessions++
		providerCounts[session.Provider]++
		if now.Before(session.ExpiresAt) {
			activeSessions++
		}
	}

	stats["total_sessions"] = totalSessions
	stats["active_sessions"] = activeSessions
	stats["provider_counts"] = providerCounts
	stats["registered_providers"] = len(sm.providers)

	return stats
}

// ExportSession exports session data for external storage
func (sm *SSOManager) ExportSession(sessionID string) ([]byte, error) {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	return json.Marshal(session)
}

// ImportSession imports session data from external storage
func (sm *SSOManager) ImportSession(data []byte) error {
	var session SSOSession
	if err := json.Unmarshal(data, &session); err != nil {
		return fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Validate session is not expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("cannot import expired session")
	}

	sm.sessions[session.ID] = &session
	return nil
}