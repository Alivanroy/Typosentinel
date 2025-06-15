package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Claims represents JWT claims
type Claims struct {
	UserID         string   `json:"user_id"`
	OrganizationID string   `json:"organization_id"`
	Role           string   `json:"role"`
	Permissions    []string `json:"permissions"`
	TokenType      string   `json:"token_type"` // "access" or "refresh"
	SessionID      string   `json:"session_id"`
	jwt.RegisteredClaims
}

// AuthService handles authentication and authorization
type AuthService struct {
	jwtSecret     []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	issuer        string
}

// Config holds authentication configuration
type Config struct {
	JWTSecret   string
	AccessTTL   time.Duration
	RefreshTTL  time.Duration
	Issuer      string
}

// NewAuthService creates a new authentication service
func NewAuthService(config Config) *AuthService {
	return &AuthService{
		jwtSecret:  []byte(config.JWTSecret),
		accessTTL:  config.AccessTTL,
		refreshTTL: config.RefreshTTL,
		issuer:     config.Issuer,
	}
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// GenerateTokenPair creates access and refresh tokens
func (a *AuthService) GenerateTokenPair(userID, organizationID, role string, permissions []string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(a.accessTTL)
	refreshExpiry := now.Add(a.refreshTTL)

	// Generate JTI for token revocation
	accessJTI := generateJTI()
	refreshJTI := generateJTI()

	// Access token claims
	accessClaims := Claims{
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           role,
		Permissions:    permissions,
		TokenType:      "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        accessJTI,
			Issuer:    a.issuer,
			Subject:   userID,
			Audience:  []string{"typosentinel-api"},
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Refresh token claims
	refreshClaims := Claims{
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           role,
		Permissions:    permissions,
		TokenType:      "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refreshJTI,
			Issuer:    a.issuer,
			Subject:   userID,
			Audience:  []string{"typosentinel-api"},
			ExpiresAt: jwt.NewNumericDate(refreshExpiry),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	// Create tokens
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	// Sign tokens
	accessTokenString, err := accessToken.SignedString(a.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshTokenString, err := refreshToken.SignedString(a.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    accessExpiry,
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken validates and parses a JWT token
func (a *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Validate token type
	if claims.TokenType != "access" {
		return nil, errors.New("invalid token type")
	}

	// Validate audience
	if claims.Audience != nil && len(claims.Audience) > 0 && claims.Audience[0] != "typosentinel-api" {
		return nil, errors.New("invalid audience")
	}

	// Validate issuer
	if claims.Issuer != a.issuer {
		return nil, errors.New("invalid issuer")
	}

	return claims, nil
}

// RefreshToken validates a refresh token and generates new token pair
func (a *AuthService) RefreshToken(refreshTokenString string) (*TokenPair, error) {
	token, err := jwt.ParseWithClaims(refreshTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}

	// Validate token type
	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid token type")
	}

	// Generate new token pair
	return a.GenerateTokenPair(claims.UserID, claims.OrganizationID, claims.Role, claims.Permissions)
}

// HashPassword hashes a password using bcrypt
func (a *AuthService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against its hash
func (a *AuthService) VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// HasPermission checks if the user has a specific permission
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == permission || p == "*" {
			return true
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func (c *Claims) HasRole(role string) bool {
	return c.Role == role || c.Role == "admin"
}

// IsAdmin checks if the user is an admin
func (c *Claims) IsAdmin() bool {
	return c.Role == "admin"
}

// generateJTI generates a unique JWT ID
func generateJTI() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Permission constants
const (
	PermissionScanCreate     = "scan:create"
	PermissionScanRead       = "scan:read"
	PermissionScanDelete     = "scan:delete"
	PermissionPackageRead    = "package:read"
	PermissionThreatRead     = "threat:read"
	PermissionPolicyCreate   = "policy:create"
	PermissionPolicyRead     = "policy:read"
	PermissionPolicyUpdate   = "policy:update"
	PermissionPolicyDelete   = "policy:delete"
	PermissionUserCreate     = "user:create"
	PermissionUserRead       = "user:read"
	PermissionUserUpdate     = "user:update"
	PermissionUserDelete     = "user:delete"
	PermissionOrgRead        = "org:read"
	PermissionOrgUpdate      = "org:update"
	PermissionMLAccess       = "ml:access"
	PermissionAdminAccess    = "admin:access"
)

// Role constants
const (
	RoleUser     = "user"
	RoleAnalyst  = "analyst"
	RoleAdmin    = "admin"
	RoleReadOnly = "readonly"
)

// GetDefaultPermissions returns default permissions for a role
func GetDefaultPermissions(role string) []string {
	switch role {
	case RoleAdmin:
		return []string{"*"} // Admin has all permissions
	case RoleAnalyst:
		return []string{
			PermissionScanCreate,
			PermissionScanRead,
			PermissionScanDelete,
			PermissionPackageRead,
			PermissionThreatRead,
			PermissionPolicyRead,
			PermissionMLAccess,
		}
	case RoleUser:
		return []string{
			PermissionScanCreate,
			PermissionScanRead,
			PermissionPackageRead,
			PermissionThreatRead,
			PermissionPolicyRead,
		}
	case RoleReadOnly:
		return []string{
			PermissionScanRead,
			PermissionPackageRead,
			PermissionThreatRead,
			PermissionPolicyRead,
		}
	default:
		return []string{}
	}
}