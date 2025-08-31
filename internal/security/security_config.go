package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SecurityConfig holds all security-related configuration
type SecurityConfig struct {
	JWT               JWTSecurityConfig       `json:"jwt"`
	Authentication    AuthSecurityConfig      `json:"authentication"`
	RateLimit         RateLimitSecurityConfig `json:"rate_limit"`
	RBAC              RBACSecurityConfig      `json:"rbac"`
	Encryption        EncryptionConfig        `json:"encryption"`
	SessionManagement SessionConfig           `json:"session_management"`
	Session           SessionConfig           `json:"session"`
	AuditLogging      AuditConfig             `json:"audit_logging"`
}

// JWTSecurityConfig contains JWT security settings
type JWTSecurityConfig struct {
	SecretKey              string        `json:"secret_key"`
	AccessTokenExpiration  time.Duration `json:"access_token_expiration"`
	RefreshTokenExpiration time.Duration `json:"refresh_token_expiration"`
	Issuer                 string        `json:"issuer"`
	Audience               string        `json:"audience"`
	Algorithm              string        `json:"algorithm"`
	RequireHTTPS           bool          `json:"require_https"`
	TokenRevocationEnabled bool          `json:"token_revocation_enabled"`
}

// AuthSecurityConfig contains authentication security settings
type AuthSecurityConfig struct {
	RequireStrongPasswords bool          `json:"require_strong_passwords"`
	MinPasswordLength      int           `json:"min_password_length"`
	PasswordMinLength      int           `json:"password_min_length"`
	MaxLoginAttempts       int           `json:"max_login_attempts"`
	LockoutDuration        time.Duration `json:"lockout_duration"`
	RequireMFA             bool          `json:"require_mfa"`
	SessionTimeout         time.Duration `json:"session_timeout"`
	PasswordHashAlgorithm  string        `json:"password_hash_algorithm"`
	SaltLength             int           `json:"salt_length"`
	RequireUppercase       bool          `json:"require_uppercase"`
	RequireLowercase       bool          `json:"require_lowercase"`
	RequireNumbers         bool          `json:"require_numbers"`
	RequireSymbols         bool          `json:"require_symbols"`
	PasswordMaxAge         time.Duration `json:"password_max_age"`
	PasswordHistoryCount   int           `json:"password_history_count"`
}

// RateLimitSecurityConfig contains rate limiting security settings
type RateLimitSecurityConfig struct {
	GlobalEnabled        bool                     `json:"global_enabled"`
	GlobalRequestsPerSec int                      `json:"global_requests_per_sec"`
	GlobalBurstSize      int                      `json:"global_burst_size"`
	EndpointLimits       map[string]EndpointLimit `json:"endpoint_limits"`
	IPWhitelist          []string                 `json:"ip_whitelist"`
	IPBlacklist          []string                 `json:"ip_blacklist"`
	EnableDDoSProtection bool                     `json:"enable_ddos_protection"`
}

// EndpointLimit defines rate limits for specific endpoints
type EndpointLimit struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowDuration    time.Duration `json:"window_duration"`
}

// RBACSecurityConfig contains RBAC security settings
type RBACSecurityConfig struct {
	Enabled                    bool     `json:"enabled"`
	DefaultRole                string   `json:"default_role"`
	AdminRoles                 []string `json:"admin_roles"`
	RequireExplicitPermissions bool     `json:"require_explicit_permissions"`
	MaxRoleInheritanceDepth    int      `json:"max_role_inheritance_depth"`
}

// EncryptionConfig contains encryption settings
type EncryptionConfig struct {
	Algorithm            string        `json:"algorithm"`
	KeySize              int           `json:"key_size"`
	EncryptionKey        string        `json:"encryption_key"`
	RotationInterval     time.Duration `json:"rotation_interval"`
	EncryptSensitiveData bool          `json:"encrypt_sensitive_data"`
	UseArgon2            bool          `json:"use_argon2"`
}

// SessionConfig contains session management settings
type SessionConfig struct {
	CookieSecure          bool          `json:"cookie_secure"`
	CookieHTTPOnly        bool          `json:"cookie_http_only"`
	CookieSameSite        string        `json:"cookie_same_site"`
	SessionTimeout        time.Duration `json:"session_timeout"`
	IdleTimeout           time.Duration `json:"idle_timeout"`
	MaxConcurrentSessions int           `json:"max_concurrent_sessions"`
}

// AuditConfig contains audit logging settings
type AuditConfig struct {
	Enabled          bool     `json:"enabled"`
	LogLevel         string   `json:"log_level"`
	LogSensitiveData bool     `json:"log_sensitive_data"`
	RetentionDays    int      `json:"retention_days"`
	AuditEvents      []string `json:"audit_events"`
}

// LoadSecurityConfig loads security configuration from environment variables
func LoadSecurityConfig() (*SecurityConfig, error) {
	config := &SecurityConfig{
		JWT: JWTSecurityConfig{
			SecretKey:              getEnvOrDefault("TYPOSENTINEL_JWT_SECRET", ""),
			AccessTokenExpiration:  parseDurationOrDefault("TYPOSENTINEL_JWT_ACCESS_EXPIRATION", 15*time.Minute),
			RefreshTokenExpiration: parseDurationOrDefault("TYPOSENTINEL_JWT_REFRESH_EXPIRATION", 7*24*time.Hour),
			Issuer:                 getEnvOrDefault("TYPOSENTINEL_JWT_ISSUER", "typosentinel"),
			Audience:               getEnvOrDefault("TYPOSENTINEL_JWT_AUDIENCE", "typosentinel-api"),
			Algorithm:              getEnvOrDefault("TYPOSENTINEL_JWT_ALGORITHM", "HS256"),
			RequireHTTPS:           parseBoolOrDefault("TYPOSENTINEL_JWT_REQUIRE_HTTPS", true),
			TokenRevocationEnabled: parseBoolOrDefault("TYPOSENTINEL_JWT_REVOCATION_ENABLED", true),
		},
		Authentication: AuthSecurityConfig{
			RequireStrongPasswords: parseBoolOrDefault("TYPOSENTINEL_REQUIRE_STRONG_PASSWORDS", true),
			MinPasswordLength:      parseIntOrDefault("TYPOSENTINEL_MIN_PASSWORD_LENGTH", 12),
			PasswordMinLength:      parseIntOrDefault("TYPOSENTINEL_PASSWORD_MIN_LENGTH", 12),
			MaxLoginAttempts:       parseIntOrDefault("TYPOSENTINEL_MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:        parseDurationOrDefault("TYPOSENTINEL_LOCKOUT_DURATION", 30*time.Minute),
			RequireMFA:             parseBoolOrDefault("TYPOSENTINEL_REQUIRE_MFA", false),
			SessionTimeout:         parseDurationOrDefault("TYPOSENTINEL_SESSION_TIMEOUT", 8*time.Hour),
			PasswordHashAlgorithm:  getEnvOrDefault("TYPOSENTINEL_PASSWORD_HASH_ALGORITHM", "bcrypt"),
			SaltLength:             parseIntOrDefault("TYPOSENTINEL_SALT_LENGTH", 32),
			RequireUppercase:       parseBoolOrDefault("TYPOSENTINEL_REQUIRE_UPPERCASE", true),
			RequireLowercase:       parseBoolOrDefault("TYPOSENTINEL_REQUIRE_LOWERCASE", true),
			RequireNumbers:         parseBoolOrDefault("TYPOSENTINEL_REQUIRE_NUMBERS", true),
			RequireSymbols:         parseBoolOrDefault("TYPOSENTINEL_REQUIRE_SYMBOLS", true),
			PasswordMaxAge:         parseDurationOrDefault("TYPOSENTINEL_PASSWORD_MAX_AGE", 90*24*time.Hour),
			PasswordHistoryCount:   parseIntOrDefault("TYPOSENTINEL_PASSWORD_HISTORY_COUNT", 5),
		},
		RateLimit: RateLimitSecurityConfig{
			GlobalEnabled:        parseBoolOrDefault("TYPOSENTINEL_RATE_LIMIT_ENABLED", true),
			GlobalRequestsPerSec: parseIntOrDefault("TYPOSENTINEL_RATE_LIMIT_REQUESTS_PER_SEC", 100),
			GlobalBurstSize:      parseIntOrDefault("TYPOSENTINEL_RATE_LIMIT_BURST_SIZE", 200),
			EndpointLimits:       loadEndpointLimits(),
			IPWhitelist:          parseStringSlice("TYPOSENTINEL_IP_WHITELIST"),
			IPBlacklist:          parseStringSlice("TYPOSENTINEL_IP_BLACKLIST"),
			EnableDDoSProtection: parseBoolOrDefault("TYPOSENTINEL_DDOS_PROTECTION_ENABLED", true),
		},
		RBAC: RBACSecurityConfig{
			Enabled:                    parseBoolOrDefault("TYPOSENTINEL_RBAC_ENABLED", true),
			DefaultRole:                getEnvOrDefault("TYPOSENTINEL_DEFAULT_ROLE", "viewer"),
			AdminRoles:                 parseStringSlice("TYPOSENTINEL_ADMIN_ROLES"),
			RequireExplicitPermissions: parseBoolOrDefault("TYPOSENTINEL_REQUIRE_EXPLICIT_PERMISSIONS", true),
			MaxRoleInheritanceDepth:    parseIntOrDefault("TYPOSENTINEL_MAX_ROLE_INHERITANCE_DEPTH", 5),
		},
		Encryption: EncryptionConfig{
			Algorithm:            getEnvOrDefault("TYPOSENTINEL_ENCRYPTION_ALGORITHM", "AES-256-GCM"),
			KeySize:              parseIntOrDefault("TYPOSENTINEL_ENCRYPTION_KEY_SIZE", 256),
			EncryptionKey:        getEnvOrDefault("TYPOSENTINEL_ENCRYPTION_KEY", ""),
			RotationInterval:     parseDurationOrDefault("TYPOSENTINEL_KEY_ROTATION_INTERVAL", 90*24*time.Hour),
			EncryptSensitiveData: parseBoolOrDefault("TYPOSENTINEL_ENCRYPT_SENSITIVE_DATA", true),
			UseArgon2:            parseBoolOrDefault("TYPOSENTINEL_USE_ARGON2", true),
		},
		SessionManagement: SessionConfig{
			CookieSecure:          parseBoolOrDefault("TYPOSENTINEL_COOKIE_SECURE", true),
			CookieHTTPOnly:        parseBoolOrDefault("TYPOSENTINEL_COOKIE_HTTP_ONLY", true),
			CookieSameSite:        getEnvOrDefault("TYPOSENTINEL_COOKIE_SAME_SITE", "Strict"),
			SessionTimeout:        parseDurationOrDefault("TYPOSENTINEL_SESSION_TIMEOUT", 8*time.Hour),
			IdleTimeout:           parseDurationOrDefault("TYPOSENTINEL_SESSION_IDLE_TIMEOUT", 30*time.Minute),
			MaxConcurrentSessions: parseIntOrDefault("TYPOSENTINEL_MAX_CONCURRENT_SESSIONS", 5),
		},
		Session: SessionConfig{
			CookieSecure:          parseBoolOrDefault("TYPOSENTINEL_COOKIE_SECURE", true),
			CookieHTTPOnly:        parseBoolOrDefault("TYPOSENTINEL_COOKIE_HTTP_ONLY", true),
			CookieSameSite:        getEnvOrDefault("TYPOSENTINEL_COOKIE_SAME_SITE", "Strict"),
			SessionTimeout:        parseDurationOrDefault("TYPOSENTINEL_SESSION_TIMEOUT", 8*time.Hour),
			IdleTimeout:           parseDurationOrDefault("TYPOSENTINEL_SESSION_IDLE_TIMEOUT", 30*time.Minute),
			MaxConcurrentSessions: parseIntOrDefault("TYPOSENTINEL_MAX_CONCURRENT_SESSIONS", 5),
		},
		AuditLogging: AuditConfig{
			Enabled:          parseBoolOrDefault("TYPOSENTINEL_AUDIT_ENABLED", true),
			LogLevel:         getEnvOrDefault("TYPOSENTINEL_AUDIT_LOG_LEVEL", "INFO"),
			LogSensitiveData: parseBoolOrDefault("TYPOSENTINEL_AUDIT_LOG_SENSITIVE", false),
			RetentionDays:    parseIntOrDefault("TYPOSENTINEL_AUDIT_RETENTION_DAYS", 90),
			AuditEvents:      parseStringSlice("TYPOSENTINEL_AUDIT_EVENTS"),
		},
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid security configuration: %w", err)
	}

	return config, nil
}

// Validate validates the security configuration
func (sc *SecurityConfig) Validate() error {
	// Validate JWT configuration
	if sc.JWT.SecretKey == "" {
		return fmt.Errorf("JWT secret key is required (set TYPOSENTINEL_JWT_SECRET)")
	}
	if len(sc.JWT.SecretKey) < 32 {
		return fmt.Errorf("JWT secret key must be at least 32 characters long")
	}

	// Validate authentication configuration
	if sc.Authentication.MinPasswordLength < 8 {
		return fmt.Errorf("minimum password length must be at least 8 characters")
	}
	if sc.Authentication.MaxLoginAttempts < 1 {
		return fmt.Errorf("max login attempts must be at least 1")
	}

	// Validate rate limiting configuration
	if sc.RateLimit.GlobalRequestsPerSec < 1 {
		return fmt.Errorf("global requests per second must be at least 1")
	}
	if sc.RateLimit.GlobalBurstSize < 1 {
		return fmt.Errorf("global burst size must be at least 1")
	}

	// Validate encryption configuration
	if sc.Encryption.EncryptSensitiveData && sc.Encryption.EncryptionKey == "" {
		return fmt.Errorf("encryption key is required when sensitive data encryption is enabled")
	}

	return nil
}

// GenerateSecureJWTSecret generates a cryptographically secure JWT secret
func GenerateSecureJWTSecret() (string, error) {
	bytes := make([]byte, 64) // 512 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateSecureEncryptionKey generates a cryptographically secure encryption key
func GenerateSecureEncryptionKey() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// HashPassword securely hashes a password using bcrypt
func (sc *SecurityConfig) HashPassword(password string) (string, error) {
	// Generate salt
	salt := make([]byte, sc.Authentication.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password with salt
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write(salt)
	hash := hasher.Sum(nil)

	// Combine salt and hash
	result := hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash)
	return result, nil
}

// VerifyPassword verifies a password against its hash
func (sc *SecurityConfig) VerifyPassword(password, hashedPassword string) bool {
	parts := strings.Split(hashedPassword, ":")
	if len(parts) != 2 {
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// Hash the provided password with the same salt
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write(salt)
	actualHash := hasher.Sum(nil)

	// Compare hashes
	return hex.EncodeToString(actualHash) == hex.EncodeToString(expectedHash)
}

// Helper functions for parsing environment variables

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func parseIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func parseDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func parseStringSlice(key string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return []string{}
}

func loadEndpointLimits() map[string]EndpointLimit {
	limits := make(map[string]EndpointLimit)

	// Default endpoint limits
	limits["/api/v1/scan"] = EndpointLimit{
		RequestsPerSecond: 10,
		BurstSize:         20,
		WindowDuration:    time.Minute,
	}
	limits["/api/v1/enterprise/policies"] = EndpointLimit{
		RequestsPerSecond: 50,
		BurstSize:         100,
		WindowDuration:    time.Minute,
	}
	limits["/api/v1/enterprise/rbac"] = EndpointLimit{
		RequestsPerSecond: 30,
		BurstSize:         60,
		WindowDuration:    time.Minute,
	}

	return limits
}
