package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"

	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// UserRole defines user roles in the system
type UserRole string

const (
	RoleGuest     UserRole = "guest"
	RoleModerator UserRole = "moderator"
	RoleSystem    UserRole = "system"
)

func (ur UserRole) String() string {
	return string(ur)
}

// Permission defines system permissions
type Permission string

const (
	// Scan permissions
	PermissionScanUpdate Permission = "scan:update"

	// Batch permissions
	PermissionBatchRead   Permission = "batch:read"
	PermissionBatchCreate Permission = "batch:create"
	PermissionBatchUpdate Permission = "batch:update"
	PermissionBatchDelete Permission = "batch:delete"

	// System permissions
	PermissionSystemRead   Permission = "system:read"
	PermissionSystemWrite  Permission = "system:write"
	PermissionSystemAdmin  Permission = "system:admin"
	PermissionSystemConfig Permission = "system:config"

	// API permissions
	PermissionAPIRead  Permission = "api:read"
	PermissionAPIWrite Permission = "api:write"
	PermissionAPIAdmin Permission = "api:admin"
)

func (p Permission) String() string {
	return string(p)
}



// APIKey represents an API key
type APIKey struct {
	ID          string                 `json:"id"`
	Key         string                 `json:"key"`
	UserID      string                 `json:"user_id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Permissions []Permission           `json:"permissions"`
	RateLimit   *RateLimit             `json:"rate_limit"`
	Metadata    map[string]interface{} `json:"metadata"`
	Active      bool                   `json:"active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastUsedAt  *time.Time             `json:"last_used_at"`
	UsageCount  int64                  `json:"usage_count"`
	ExpiresAt   *time.Time             `json:"expires_at"`
}

// RateLimit defines rate limiting for API keys
type RateLimit struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour"`
	RequestsPerDay    int           `json:"requests_per_day"`
	BurstLimit        int           `json:"burst_limit"`
	Window            time.Duration `json:"window"`
}

// Session represents a user session
type Session struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Token     string                 `json:"token"`
	RefreshToken string              `json:"refresh_token"`
	ClientIP  string                 `json:"client_ip"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata"`
	Active    bool                   `json:"active"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	LastAccessAt time.Time           `json:"last_access_at"`
}

// Claims is defined in auth.go

// AuthManager manages authentication and authorization
type AuthManager struct {
	users       map[string]*User
	passwordHashes map[string]string
	apiKeys     map[string]*APIKey
	sessions    map[string]*Session
	redis       *redis.Client
	metrics     *metrics.Metrics
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	apiKeysMu   sync.RWMutex
	sessionsMu  sync.RWMutex
	config      *AuthConfig
	running     bool
	rolePermissions map[UserRole][]Permission
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	JWTSecret           string        `json:"jwt_secret"`
	JWTExpiration       time.Duration `json:"jwt_expiration"`
	RefreshTokenExpiration time.Duration `json:"refresh_token_expiration"`
	SessionTimeout      time.Duration `json:"session_timeout"`
	PasswordMinLength   int           `json:"password_min_length"`
	PasswordRequireSpecial bool       `json:"password_require_special"`
	PasswordRequireNumber  bool       `json:"password_require_number"`
	PasswordRequireUpper   bool       `json:"password_require_upper"`
	PasswordRequireLower   bool       `json:"password_require_lower"`
	MaxLoginAttempts    int           `json:"max_login_attempts"`
	LockoutDuration     time.Duration `json:"lockout_duration"`
	APIKeyLength        int           `json:"api_key_length"`
	APIKeyPrefix        string        `json:"api_key_prefix"`
	RedisKeyPrefix      string        `json:"redis_key_prefix"`
	EnableRedisSync     bool          `json:"enable_redis_sync"`
	EnableMetrics       bool          `json:"enable_metrics"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
}



// CreateAPIKeyRequest represents an API key creation request
type CreateAPIKeyRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Permissions []Permission           `json:"permissions"`
	RateLimit   *RateLimit             `json:"rate_limit"`
	Metadata    map[string]interface{} `json:"metadata"`
	ExpiresAt   *time.Time             `json:"expires_at"`
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(config *AuthConfig, redis *redis.Client) *AuthManager {
	ctx, cancel := context.WithCancel(context.Background())

	// Set default values
	if config.JWTExpiration == 0 {
		config.JWTExpiration = 24 * time.Hour
	}
	if config.RefreshTokenExpiration == 0 {
		config.RefreshTokenExpiration = 7 * 24 * time.Hour
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 30 * time.Minute
	}
	if config.PasswordMinLength == 0 {
		config.PasswordMinLength = 8
	}
	if config.MaxLoginAttempts == 0 {
		config.MaxLoginAttempts = 5
	}
	if config.LockoutDuration == 0 {
		config.LockoutDuration = 15 * time.Minute
	}
	if config.APIKeyLength == 0 {
		config.APIKeyLength = 32
	}
	if config.APIKeyPrefix == "" {
		config.APIKeyPrefix = "ts_"
	}
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "typosentinel:auth:"
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Hour
	}

	am := &AuthManager{
		users:    make(map[string]*User),
		passwordHashes: make(map[string]string),
		apiKeys:  make(map[string]*APIKey),
		sessions: make(map[string]*Session),
		redis:    redis,
		metrics:  metrics.GetInstance(),
		ctx:      ctx,
		cancel:   cancel,
		config:   config,
		rolePermissions: make(map[UserRole][]Permission),
	}

	// Initialize role permissions
	am.initializeRolePermissions()

	return am
}

// Start starts the authentication manager
func (am *AuthManager) Start() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.running {
		return fmt.Errorf("auth manager is already running")
	}

	// Load data from Redis if enabled
	if am.config.EnableRedisSync && am.redis != nil {
		if err := am.loadFromRedis(); err != nil {
			log.Printf("Failed to load auth data from Redis: %v", err)
		}
	}

	// Start cleanup routine
	go am.cleanupRoutine()

	am.running = true
	log.Println("Authentication manager started")
	return nil
}

// Stop stops the authentication manager
func (am *AuthManager) Stop() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.running {
		return fmt.Errorf("auth manager is not running")
	}

	am.cancel()
	am.running = false
	log.Println("Authentication manager stopped")
	return nil
}

// CreateUser creates a new user
func (am *AuthManager) CreateUser(req *CreateUserRequest) (*User, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Validate username uniqueness
	for _, user := range am.users {
		if user.Username == req.Username {
			return nil, fmt.Errorf("username already exists: %s", req.Username)
		}
		if user.Email == req.Email {
			return nil, fmt.Errorf("email already exists: %s", req.Email)
		}
	}

	// Validate password
	if err := am.validatePassword(req.Password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Hash password
	passwordHash, err := am.hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &User{
		ID:             uuid.New(),
		Username:       req.Username,
		Email:          req.Email,
		FullName:       req.FullName,
		Role:           string(req.Role),
		OrganizationID: req.OrganizationID,
		IsActive:       true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Store password hash separately (not in User struct)
	am.storePasswordHash(user.ID.String(), passwordHash)

	am.users[user.ID.String()] = user

	// Store in Redis if enabled
	if am.config.EnableRedisSync && am.redis != nil {
		go am.storeUserInRedis(user)
	}

	// Update metrics
	if am.config.EnableMetrics {
		am.metrics.UsersCreated.WithLabelValues(string(user.Role)).Inc()
	}

	log.Printf("Created user: %s (ID: %s, Role: %s)", user.Username, user.ID, user.Role)
	return user, nil
}

// Login authenticates a user and creates a session
func (am *AuthManager) Login(req *LoginRequest) (*LoginResponse, error) {
	// Find user by username
	user := am.findUserByUsername(req.Username)
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("user account is disabled")
	}

	// Verify password
	passwordHash := am.getPasswordHash(user.ID.String())
	if !am.verifyPassword(req.Password, passwordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Create session
	session, err := am.createSession(user, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate JWT token
	token, err := am.generateJWT(user, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := am.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Update session with tokens
	session.Token = token
	session.RefreshToken = refreshToken

	// Update user login info
	now := time.Now()
	user.LastLogin = &now
	user.UpdatedAt = now

	// Store session
	am.sessionsMu.Lock()
	am.sessions[session.ID] = session
	am.sessionsMu.Unlock()

	// Store in Redis if enabled
	if am.config.EnableRedisSync && am.redis != nil {
		go am.storeSessionInRedis(session)
		go am.storeUserInRedis(user)
	}

	// Update metrics
	if am.config.EnableMetrics {
		am.metrics.UserLogins.WithLabelValues(string(user.Role)).Inc()
	}

	log.Printf("User logged in: %s (ID: %s)", user.Username, user.ID)

	tokens := &TokenPair{
		AccessToken:  token,
		RefreshToken: refreshToken,
		ExpiresAt:    session.ExpiresAt,
		TokenType:    "Bearer",
	}

	return &LoginResponse{
		User:   user,
		Tokens: tokens,
	}, nil
}

// Logout invalidates a session
func (am *AuthManager) Logout(sessionID string) error {
	am.sessionsMu.Lock()
	defer am.sessionsMu.Unlock()

	session, exists := am.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	session.Active = false
	delete(am.sessions, sessionID)

	// Remove from Redis if enabled
	if am.config.EnableRedisSync && am.redis != nil {
		go am.deleteSessionFromRedis(sessionID)
	}

	log.Printf("User logged out: session %s", sessionID)
	return nil
}

// ValidateToken validates a JWT token
func (am *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(am.config.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if session is still active
	am.sessionsMu.RLock()
	session, exists := am.sessions[claims.SessionID]
	am.sessionsMu.RUnlock()

	if !exists || !session.Active {
		return nil, fmt.Errorf("session not found or inactive")
	}

	// Update last access time
	session.LastAccessAt = time.Now()

	return claims, nil
}

// ValidateAPIKey validates an API key
func (am *AuthManager) ValidateAPIKey(keyString string) (*APIKey, error) {
	am.apiKeysMu.RLock()
	defer am.apiKeysMu.RUnlock()

	for _, apiKey := range am.apiKeys {
		if apiKey.Key == keyString && apiKey.Active {
			// Check expiration
			if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
				return nil, fmt.Errorf("API key expired")
			}

			// Update usage info
			now := time.Now()
			apiKey.LastUsedAt = &now
			apiKey.UsageCount++
			apiKey.UpdatedAt = now

			// Store in Redis if enabled
			if am.config.EnableRedisSync && am.redis != nil {
				go am.storeAPIKeyInRedis(apiKey)
			}

			return apiKey, nil
		}
	}

	return nil, fmt.Errorf("invalid API key")
}

// CreateAPIKey creates a new API key for a user
func (am *AuthManager) CreateAPIKey(userID string, req *CreateAPIKeyRequest) (*APIKey, error) {
	am.mu.RLock()
	user, exists := am.users[userID]
	am.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	// Generate API key
	keyString, err := am.generateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	apiKey := &APIKey{
		ID:          am.generateAPIKeyID(),
		Key:         keyString,
		UserID:      userID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		RateLimit:   req.RateLimit,
		Metadata:    req.Metadata,
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		UsageCount:  0,
		ExpiresAt:   req.ExpiresAt,
	}

	am.apiKeysMu.Lock()
	am.apiKeys[apiKey.ID] = apiKey
	am.apiKeysMu.Unlock()

	// Update user timestamp
	am.mu.Lock()
	user.UpdatedAt = time.Now()
	am.mu.Unlock()

	// Store in Redis if enabled
	if am.config.EnableRedisSync && am.redis != nil {
		go am.storeAPIKeyInRedis(apiKey)
		go am.storeUserInRedis(user)
	}

	// Update metrics
	if am.config.EnableMetrics {
		am.metrics.APIKeysCreated.WithLabelValues(userID).Inc()
	}

	log.Printf("Created API key: %s for user %s", apiKey.Name, userID)
	return apiKey, nil
}

// RevokeAPIKey revokes an API key
func (am *AuthManager) RevokeAPIKey(apiKeyID string) error {
	am.apiKeysMu.Lock()
	defer am.apiKeysMu.Unlock()

	apiKey, exists := am.apiKeys[apiKeyID]
	if !exists {
		return fmt.Errorf("API key not found")
	}

	apiKey.Active = false
	apiKey.UpdatedAt = time.Now()

	// Store in Redis if enabled
	if am.config.EnableRedisSync && am.redis != nil {
		go am.storeAPIKeyInRedis(apiKey)
	}

	log.Printf("Revoked API key: %s", apiKeyID)
	return nil
}

// HasPermission checks if a user has a specific permission
func (am *AuthManager) HasPermission(userID string, permission Permission) bool {
	am.mu.RLock()
	user, exists := am.users[userID]
	am.mu.RUnlock()

	if !exists || !user.IsActive {
		return false
	}

	// Check role permissions
	if rolePerms, exists := am.rolePermissions[UserRole(user.Role)]; exists {
		for _, p := range rolePerms {
			if p == permission {
				return true
			}
		}
	}

	return false
}

// HasAPIKeyPermission checks if an API key has a specific permission
func (am *AuthManager) HasAPIKeyPermission(apiKeyID string, permission Permission) bool {
	am.apiKeysMu.RLock()
	apiKey, exists := am.apiKeys[apiKeyID]
	am.apiKeysMu.RUnlock()

	if !exists || !apiKey.Active {
		return false
	}

	// Check API key permissions
	for _, p := range apiKey.Permissions {
		if p == permission {
			return true
		}
	}

	// Check user permissions
	return am.HasPermission(apiKey.UserID, permission)
}

// GetUser returns a user by ID
func (am *AuthManager) GetUser(userID string) (*User, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	user, exists := am.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// GetUserByUsername returns a user by username
func (am *AuthManager) GetUserByUsername(username string) (*User, error) {
	user := am.findUserByUsername(username)
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// GetAPIKey returns an API key by ID
func (am *AuthManager) GetAPIKey(apiKeyID string) (*APIKey, error) {
	am.apiKeysMu.RLock()
	defer am.apiKeysMu.RUnlock()

	apiKey, exists := am.apiKeys[apiKeyID]
	if !exists {
		return nil, fmt.Errorf("API key not found")
	}

	return apiKey, nil
}

// GetSession returns a session by ID
func (am *AuthManager) GetSession(sessionID string) (*Session, error) {
	am.sessionsMu.RLock()
	defer am.sessionsMu.RUnlock()

	session, exists := am.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	return session, nil
}

// Helper methods

// initializeRolePermissions sets up default permissions for each role
func (am *AuthManager) initializeRolePermissions() {
	am.rolePermissions[RoleGuest] = []Permission{
		PermissionScanRead,
	}

	am.rolePermissions[RoleUser] = []Permission{
		PermissionScanRead,
		PermissionScanCreate,
		PermissionBatchRead,
		PermissionBatchCreate,
		PermissionAPIRead,
	}

	am.rolePermissions[RoleModerator] = []Permission{
		PermissionScanRead,
		PermissionScanCreate,
		PermissionScanUpdate,
		PermissionBatchRead,
		PermissionBatchCreate,
		PermissionBatchUpdate,
		PermissionUserRead,
		PermissionAPIRead,
		PermissionAPIWrite,
	}

	am.rolePermissions[RoleAdmin] = []Permission{
		PermissionScanRead,
		PermissionScanCreate,
		PermissionScanUpdate,
		PermissionScanDelete,
		PermissionBatchRead,
		PermissionBatchCreate,
		PermissionBatchUpdate,
		PermissionBatchDelete,
		PermissionUserRead,
		PermissionUserCreate,
		PermissionUserUpdate,
		PermissionUserDelete,
		PermissionSystemRead,
		PermissionSystemWrite,
		PermissionSystemAdmin,
		PermissionSystemConfig,
		PermissionAPIRead,
		PermissionAPIWrite,
		PermissionAPIAdmin,
	}

	am.rolePermissions[RoleSystem] = []Permission{
		PermissionSystemRead,
		PermissionSystemWrite,
		PermissionSystemAdmin,
		PermissionSystemConfig,
	}
}

// findUserByUsername finds a user by username
func (am *AuthManager) findUserByUsername(username string) *User {
	am.mu.RLock()
	defer am.mu.RUnlock()

	for _, user := range am.users {
		if user.Username == username {
			return user
		}
	}
	return nil
}

// validatePassword validates password strength
func (am *AuthManager) validatePassword(password string) error {
	if len(password) < am.config.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters long", am.config.PasswordMinLength)
	}

	if am.config.PasswordRequireSpecial {
		if !strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	if am.config.PasswordRequireNumber {
		if !strings.ContainsAny(password, "0123456789") {
			return fmt.Errorf("password must contain at least one number")
		}
	}

	if am.config.PasswordRequireUpper {
		if !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	if am.config.PasswordRequireLower {
		if !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
			return fmt.Errorf("password must contain at least one lowercase letter")
		}
	}

	return nil
}

// hashPassword hashes a password using bcrypt
func (am *AuthManager) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// verifyPassword verifies a password against its hash
func (am *AuthManager) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// createSession creates a new session
func (am *AuthManager) createSession(user *User, clientIP, userAgent string) (*Session, error) {
	session := &Session{
		ID:        am.generateSessionID(),
		UserID:    user.ID.String(),
		ClientIP:  clientIP,
		UserAgent: userAgent,
		Metadata:  make(map[string]interface{}),
		Active:    true,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(am.config.JWTExpiration),
		LastAccessAt: time.Now(),
	}

	return session, nil
}

// generateJWT generates a JWT token
func (am *AuthManager) generateJWT(user *User, sessionID string) (string, error) {
	// Get role-based permissions
	rolePerms := am.rolePermissions[UserRole(user.Role)]
	permissions := make([]string, len(rolePerms))
	for i, perm := range rolePerms {
		permissions[i] = string(perm)
	}

	claims := &Claims{
		UserID:      user.ID.String(),
		Role:        string(user.Role),
		Permissions: permissions,
		SessionID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(am.config.JWTExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "typosentinel",
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(am.config.JWTSecret))
}

// generateRefreshToken generates a refresh token
func (am *AuthManager) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// generateAPIKey generates an API key
func (am *AuthManager) generateAPIKey() (string, error) {
	bytes := make([]byte, am.config.APIKeyLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return am.config.APIKeyPrefix + hex.EncodeToString(bytes), nil
}

// generateUserID generates a unique user ID
func (am *AuthManager) generateUserID() string {
	return fmt.Sprintf("user_%d_%s", time.Now().UnixNano(), am.generateRandomString(8))
}

// generateAPIKeyID generates a unique API key ID
func (am *AuthManager) generateAPIKeyID() string {
	return fmt.Sprintf("key_%d_%s", time.Now().UnixNano(), am.generateRandomString(8))
}

// generateSessionID generates a unique session ID
func (am *AuthManager) generateSessionID() string {
	return fmt.Sprintf("sess_%d_%s", time.Now().UnixNano(), am.generateRandomString(8))
}

// storePasswordHash stores a password hash for a user
func (am *AuthManager) storePasswordHash(userID, passwordHash string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.passwordHashes[userID] = passwordHash
}

// getPasswordHash retrieves a password hash for a user
func (am *AuthManager) getPasswordHash(userID string) string {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.passwordHashes[userID]
}

// generateRandomString generates a random string of specified length
func (am *AuthManager) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

// mergePermissions merges two permission slices
func (am *AuthManager) mergePermissions(perms1, perms2 []Permission) []Permission {
	permMap := make(map[Permission]bool)

	// Add permissions from first slice
	for _, perm := range perms1 {
		permMap[perm] = true
	}

	// Add permissions from second slice
	for _, perm := range perms2 {
		permMap[perm] = true
	}

	// Convert back to slice
	var merged []Permission
	for perm := range permMap {
		merged = append(merged, perm)
	}

	return merged
}

// Redis operations

// loadFromRedis loads authentication data from Redis
func (am *AuthManager) loadFromRedis() error {
	// Load users
	userKeys, err := am.redis.Keys(am.ctx, am.config.RedisKeyPrefix+"users:*").Result()
	if err != nil {
		return fmt.Errorf("failed to get user keys: %w", err)
	}

	for _, key := range userKeys {
		userData, err := am.redis.Get(am.ctx, key).Result()
		if err != nil {
			log.Printf("Failed to get user data for key %s: %v", key, err)
			continue
		}

		var user User
		if err := json.Unmarshal([]byte(userData), &user); err != nil {
			log.Printf("Failed to unmarshal user data: %v", err)
			continue
		}

		am.users[user.ID.String()] = &user
	}

	// Load API keys
	apiKeyKeys, err := am.redis.Keys(am.ctx, am.config.RedisKeyPrefix+"apikeys:*").Result()
	if err != nil {
		return fmt.Errorf("failed to get API key keys: %w", err)
	}

	for _, key := range apiKeyKeys {
		apiKeyData, err := am.redis.Get(am.ctx, key).Result()
		if err != nil {
			log.Printf("Failed to get API key data for key %s: %v", key, err)
			continue
		}

		var apiKey APIKey
		if err := json.Unmarshal([]byte(apiKeyData), &apiKey); err != nil {
			log.Printf("Failed to unmarshal API key data: %v", err)
			continue
		}

		am.apiKeys[apiKey.ID] = &apiKey
	}

	// Load sessions
	sessionKeys, err := am.redis.Keys(am.ctx, am.config.RedisKeyPrefix+"sessions:*").Result()
	if err != nil {
		return fmt.Errorf("failed to get session keys: %w", err)
	}

	for _, key := range sessionKeys {
		sessionData, err := am.redis.Get(am.ctx, key).Result()
		if err != nil {
			log.Printf("Failed to get session data for key %s: %v", key, err)
			continue
		}

		var session Session
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			log.Printf("Failed to unmarshal session data: %v", err)
			continue
		}

		am.sessions[session.ID] = &session
	}

	log.Printf("Loaded %d users, %d API keys, %d sessions from Redis",
		len(am.users), len(am.apiKeys), len(am.sessions))
	return nil
}

// storeUserInRedis stores a user in Redis
func (am *AuthManager) storeUserInRedis(user *User) {
	key := am.config.RedisKeyPrefix + "users:" + user.ID.String()
	data, err := json.Marshal(user)
	if err != nil {
		log.Printf("Failed to marshal user: %v", err)
		return
	}

	if err := am.redis.Set(am.ctx, key, data, 0).Err(); err != nil {
		log.Printf("Failed to store user in Redis: %v", err)
	}
}

// storeAPIKeyInRedis stores an API key in Redis
func (am *AuthManager) storeAPIKeyInRedis(apiKey *APIKey) {
	key := am.config.RedisKeyPrefix + "apikeys:" + apiKey.ID
	data, err := json.Marshal(apiKey)
	if err != nil {
		log.Printf("Failed to marshal API key: %v", err)
		return
	}

	if err := am.redis.Set(am.ctx, key, data, 0).Err(); err != nil {
		log.Printf("Failed to store API key in Redis: %v", err)
	}
}

// storeSessionInRedis stores a session in Redis
func (am *AuthManager) storeSessionInRedis(session *Session) {
	key := am.config.RedisKeyPrefix + "sessions:" + session.ID
	data, err := json.Marshal(session)
	if err != nil {
		log.Printf("Failed to marshal session: %v", err)
		return
	}

	// Set with expiration
	ttl := time.Until(session.ExpiresAt)
	if err := am.redis.Set(am.ctx, key, data, ttl).Err(); err != nil {
		log.Printf("Failed to store session in Redis: %v", err)
	}
}

// deleteSessionFromRedis deletes a session from Redis
func (am *AuthManager) deleteSessionFromRedis(sessionID string) {
	key := am.config.RedisKeyPrefix + "sessions:" + sessionID
	if err := am.redis.Del(am.ctx, key).Err(); err != nil {
		log.Printf("Failed to delete session from Redis: %v", err)
	}
}

// cleanupRoutine periodically cleans up expired sessions
func (am *AuthManager) cleanupRoutine() {
	ticker := time.NewTicker(am.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.cleanupExpiredSessions()
		case <-am.ctx.Done():
			return
		}
	}
}

// cleanupExpiredSessions removes expired sessions
func (am *AuthManager) cleanupExpiredSessions() {
	am.sessionsMu.Lock()
	defer am.sessionsMu.Unlock()

	now := time.Now()
	expiredSessions := make([]string, 0)

	for sessionID, session := range am.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	for _, sessionID := range expiredSessions {
		delete(am.sessions, sessionID)
		if am.config.EnableRedisSync && am.redis != nil {
			go am.deleteSessionFromRedis(sessionID)
		}
	}

	if len(expiredSessions) > 0 {
		log.Printf("Cleaned up %d expired sessions", len(expiredSessions))
	}
}

// IsRunning returns whether the auth manager is running
func (am *AuthManager) IsRunning() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.running
}

// Shutdown gracefully shuts down the auth manager
func (am *AuthManager) Shutdown() error {
	log.Println("Shutting down authentication manager...")
	am.cancel()
	am.running = false
	log.Println("Authentication manager shutdown complete")
	return nil
}