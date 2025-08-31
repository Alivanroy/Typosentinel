package auth

import (
	"context"
	"errors"
	"time"
)

// User represents an authenticated user
type User struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name"`
	Roles       []string          `json:"roles"`
	Groups      []string          `json:"groups"`
	Attributes  map[string]string `json:"attributes"`
	CreatedAt   time.Time         `json:"created_at"`
	LastLoginAt *time.Time        `json:"last_login_at"`
	IsActive    bool              `json:"is_active"`
}

// Session represents an authenticated session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	// Authenticate authenticates a user with username/password
	Authenticate(ctx context.Context, username, password string) (*User, error)

	// ValidateToken validates an authentication token
	ValidateToken(ctx context.Context, token string) (*User, error)

	// GetUser retrieves user information by ID
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetUserByUsername retrieves user information by username
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// RefreshToken refreshes an authentication token
	RefreshToken(ctx context.Context, token string) (string, error)

	// Logout invalidates a session
	Logout(ctx context.Context, token string) error

	// GetProviderType returns the provider type
	GetProviderType() string
}

// SessionManager manages user sessions
type SessionManager interface {
	// CreateSession creates a new session for a user
	CreateSession(ctx context.Context, user *User, ipAddress, userAgent string) (*Session, error)

	// GetSession retrieves a session by token
	GetSession(ctx context.Context, token string) (*Session, error)

	// RefreshSession refreshes a session
	RefreshSession(ctx context.Context, token string) (*Session, error)

	// InvalidateSession invalidates a session
	InvalidateSession(ctx context.Context, token string) error

	// CleanupExpiredSessions removes expired sessions
	CleanupExpiredSessions(ctx context.Context) error
}

// AuthManager manages authentication and authorization
type AuthManager struct {
	providers       map[string]AuthProvider
	sessionManager  SessionManager
	defaultProvider string
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	DefaultProvider string                    `yaml:"default_provider" json:"default_provider"`
	Providers       map[string]ProviderConfig `yaml:"providers" json:"providers"`
	Session         SessionConfig             `yaml:"session" json:"session"`
}

// ProviderConfig holds provider-specific configuration
type ProviderConfig struct {
	Type     string                 `yaml:"type" json:"type"`
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
}

// SessionConfig holds session configuration
type SessionConfig struct {
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	RefreshTimeout time.Duration `yaml:"refresh_timeout" json:"refresh_timeout"`
	SecretKey      string        `yaml:"secret_key" json:"secret_key"`
	Secure         bool          `yaml:"secure" json:"secure"`
	SameSite       string        `yaml:"same_site" json:"same_site"`
}

// Common errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrProviderNotFound   = errors.New("provider not found")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
)

// NewAuthManager creates a new authentication manager
func NewAuthManager(config AuthConfig, sessionManager SessionManager) *AuthManager {
	return &AuthManager{
		providers:       make(map[string]AuthProvider),
		sessionManager:  sessionManager,
		defaultProvider: config.DefaultProvider,
	}
}

// RegisterProvider registers an authentication provider
func (am *AuthManager) RegisterProvider(name string, provider AuthProvider) {
	am.providers[name] = provider
}

// GetProvider returns a provider by name
func (am *AuthManager) GetProvider(name string) (AuthProvider, error) {
	provider, exists := am.providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

// Authenticate authenticates a user using the specified provider
func (am *AuthManager) Authenticate(ctx context.Context, providerName, username, password string) (*User, error) {
	if providerName == "" {
		providerName = am.defaultProvider
	}

	provider, err := am.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	return provider.Authenticate(ctx, username, password)
}

// ValidateToken validates a token using the appropriate provider
func (am *AuthManager) ValidateToken(ctx context.Context, token string) (*User, error) {
	// Try to get session first
	session, err := am.sessionManager.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionExpired
	}

	// Get user from default provider
	provider, err := am.GetProvider(am.defaultProvider)
	if err != nil {
		return nil, err
	}

	return provider.GetUser(ctx, session.UserID)
}

// CreateSession creates a new session for a user
func (am *AuthManager) CreateSession(ctx context.Context, user *User, ipAddress, userAgent string) (*Session, error) {
	return am.sessionManager.CreateSession(ctx, user, ipAddress, userAgent)
}

// RefreshSession refreshes a session
func (am *AuthManager) RefreshSession(ctx context.Context, token string) (*Session, error) {
	return am.sessionManager.RefreshSession(ctx, token)
}

// Logout logs out a user by invalidating their session
func (am *AuthManager) Logout(ctx context.Context, token string) error {
	return am.sessionManager.InvalidateSession(ctx, token)
}

// GetUser retrieves user information
func (am *AuthManager) GetUser(ctx context.Context, userID string) (*User, error) {
	provider, err := am.GetProvider(am.defaultProvider)
	if err != nil {
		return nil, err
	}

	return provider.GetUser(ctx, userID)
}

// HasRole checks if a user has a specific role
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if a user has any of the specified roles
func (u *User) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

// InGroup checks if a user is in a specific group
func (u *User) InGroup(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// InAnyGroup checks if a user is in any of the specified groups
func (u *User) InAnyGroup(groups ...string) bool {
	for _, group := range groups {
		if u.InGroup(group) {
			return true
		}
	}
	return false
}
