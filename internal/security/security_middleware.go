package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// SecurityMiddleware provides comprehensive security controls
type SecurityMiddleware struct {
	config          *SecurityConfig
	logger          *logger.Logger
	rbacEngine      *auth.RBACEngine
	rateLimiters    map[string]*rate.Limiter
	rateLimiterMu   sync.RWMutex
	loginAttempts   map[string]*LoginAttemptTracker
	loginAttemptsMu sync.RWMutex
	revokedTokens   map[string]time.Time
	revokedTokensMu sync.RWMutex
}

// LoginAttemptTracker tracks login attempts for rate limiting
type LoginAttemptTracker struct {
	Attempts    int
	LastAttempt time.Time
	LockedUntil time.Time
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	ID        string `json:"jti"`
}

// NewSecurityMiddleware creates a new security middleware instance
func NewSecurityMiddleware(config *SecurityConfig, logger *logger.Logger, rbacEngine *auth.RBACEngine) *SecurityMiddleware {
	sm := &SecurityMiddleware{
		config:        config,
		logger:        logger,
		rbacEngine:    rbacEngine,
		rateLimiters:  make(map[string]*rate.Limiter),
		loginAttempts: make(map[string]*LoginAttemptTracker),
		revokedTokens: make(map[string]time.Time),
	}

	// Start cleanup routines
	go sm.cleanupRoutine()

	return sm
}

// SecurityHeaders adds security headers to responses
func (sm *SecurityMiddleware) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")

		if sm.config.JWT.RequireHTTPS {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Remove server information
		c.Header("Server", "")
		c.Header("X-Powered-By", "")

		c.Next()
	}
}

// EnhancedRateLimit provides enhanced rate limiting with IP-based controls
func (sm *SecurityMiddleware) EnhancedRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !sm.config.RateLimit.GlobalEnabled {
			c.Next()
			return
		}

		clientIP := c.ClientIP()

		// Check IP whitelist
		if sm.isIPWhitelisted(clientIP) {
			c.Next()
			return
		}

		// Check IP blacklist
		if sm.isIPBlacklisted(clientIP) {
			sm.logger.Warn("Blocked request from blacklisted IP", map[string]interface{}{
				"ip":   clientIP,
				"path": c.Request.URL.Path,
			})
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
			})
			c.Abort()
			return
		}

		// Get rate limiter for this IP
		limiter := sm.getRateLimiter(clientIP)

		// Check rate limit
		if !limiter.Allow() {
			sm.logger.Warn("Rate limit exceeded", map[string]interface{}{
				"ip":   clientIP,
				"path": c.Request.URL.Path,
			})

			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", sm.config.RateLimit.GlobalRequestsPerSec))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Second).Unix()))

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests. Please try again later.",
				"retry_after": 1,
			})
			c.Abort()
			return
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", sm.config.RateLimit.GlobalRequestsPerSec))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", sm.config.RateLimit.GlobalRequestsPerSec-1))

		c.Next()
	}
}

// EnhancedJWTAuth provides enhanced JWT authentication with token revocation
func (sm *SecurityMiddleware) EnhancedJWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Check Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		token := parts[1]

		// Validate JWT token
		claims, err := sm.validateJWTToken(token)
		if err != nil {
			sm.logger.Warn("JWT validation failed", map[string]interface{}{
				"error": err.Error(),
				"ip":    c.ClientIP(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Check if token is revoked
		if sm.isTokenRevoked(claims.ID) {
			sm.logger.Warn("Revoked token used", map[string]interface{}{
				"token_id": claims.ID,
				"user_id":  claims.UserID,
				"ip":       c.ClientIP(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token has been revoked",
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("user_role", claims.Role)
		c.Set("token_id", claims.ID)

		c.Next()
	}
}

// RequirePermission checks if the user has the required permission
func (sm *SecurityMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if sm.rbacEngine == nil {
			sm.logger.Error("RBAC engine not available", map[string]interface{}{})
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Authorization service unavailable",
			})
			c.Abort()
			return
		}

		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			c.Abort()
			return
		}

		username, _ := c.Get("username")
		userRole, _ := c.Get("user_role")

		user := &auth.User{
			ID:       userID.(string),
			Username: username.(string),
			Roles:    []string{userRole.(string)},
		}

		// Check permission
		hasPermission := sm.rbacEngine.CheckPermission(c.Request.Context(), user, auth.Permission(permission))
		if !hasPermission {
			sm.logger.Warn("Permission denied", map[string]interface{}{
				"user_id":    userID,
				"permission": permission,
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
			})
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// LoginAttemptLimiter limits login attempts to prevent brute force attacks
func (sm *SecurityMiddleware) LoginAttemptLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to login endpoints
		if !strings.Contains(c.Request.URL.Path, "login") && !strings.Contains(c.Request.URL.Path, "auth") {
			c.Next()
			return
		}

		clientIP := c.ClientIP()

		sm.loginAttemptsMu.Lock()
		tracker, exists := sm.loginAttempts[clientIP]
		if !exists {
			tracker = &LoginAttemptTracker{}
			sm.loginAttempts[clientIP] = tracker
		}
		sm.loginAttemptsMu.Unlock()

		// Check if IP is locked out
		if time.Now().Before(tracker.LockedUntil) {
			sm.logger.Warn("Login attempt from locked IP", map[string]interface{}{
				"ip":           clientIP,
				"locked_until": tracker.LockedUntil,
			})
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Account temporarily locked",
				"retry_after": int(tracker.LockedUntil.Sub(time.Now()).Seconds()),
			})
			c.Abort()
			return
		}

		// Store original writer to intercept response
		originalWriter := c.Writer
		responseWriter := &responseWriter{ResponseWriter: originalWriter, statusCode: http.StatusOK}
		c.Writer = responseWriter

		c.Next()

		// Check if login failed (status 401 or 403)
		if responseWriter.statusCode == http.StatusUnauthorized || responseWriter.statusCode == http.StatusForbidden {
			sm.loginAttemptsMu.Lock()
			tracker.Attempts++
			tracker.LastAttempt = time.Now()

			if tracker.Attempts >= sm.config.Authentication.MaxLoginAttempts {
				tracker.LockedUntil = time.Now().Add(sm.config.Authentication.LockoutDuration)
				sm.logger.Warn("IP locked due to too many failed login attempts", map[string]interface{}{
					"ip":           clientIP,
					"attempts":     tracker.Attempts,
					"locked_until": tracker.LockedUntil,
				})
			}
			sm.loginAttemptsMu.Unlock()
		} else if responseWriter.statusCode == http.StatusOK {
			// Reset attempts on successful login
			sm.loginAttemptsMu.Lock()
			delete(sm.loginAttempts, clientIP)
			sm.loginAttemptsMu.Unlock()
		}
	}
}

// AuditLogger logs security-relevant events
func (sm *SecurityMiddleware) AuditLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !sm.config.AuditLogging.Enabled {
			c.Next()
			return
		}

		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		// Log security-relevant events
		if sm.shouldAuditEvent(path, method, c.Writer.Status()) {
			userID, _ := c.Get("user_id")
			username, _ := c.Get("username")

			auditData := map[string]interface{}{
				"timestamp":  start.UTC(),
				"method":     method,
				"path":       path,
				"status":     c.Writer.Status(),
				"duration":   time.Since(start).Milliseconds(),
				"client_ip":  c.ClientIP(),
				"user_agent": c.Request.UserAgent(),
			}

			if userID != nil {
				auditData["user_id"] = userID
			}
			if username != nil {
				auditData["username"] = username
			}

			sm.logger.Info("Security audit event", auditData)
		}
	}
}

// RevokeToken revokes a JWT token
func (sm *SecurityMiddleware) RevokeToken(tokenID string) {
	if !sm.config.JWT.TokenRevocationEnabled {
		return
	}

	sm.revokedTokensMu.Lock()
	sm.revokedTokens[tokenID] = time.Now()
	sm.revokedTokensMu.Unlock()

	sm.logger.Info("Token revoked", map[string]interface{}{
		"token_id": tokenID,
	})
}

// Helper methods

func (sm *SecurityMiddleware) validateJWTToken(tokenString string) (*TokenClaims, error) {
	// Split token into parts (header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	// Parse claims
	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	// Check expiration
	if claims.ExpiresAt > 0 && claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	// Verify signature
	expectedSignature := sm.generateTokenSignature(parts[0], parts[1])
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid token signature")
	}

	return &claims, nil
}

func (sm *SecurityMiddleware) generateTokenSignature(header, payload string) string {
	h := hmac.New(sha256.New, []byte(sm.config.JWT.SecretKey))
	h.Write([]byte(header + "." + payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (sm *SecurityMiddleware) isTokenRevoked(tokenID string) bool {
	if !sm.config.JWT.TokenRevocationEnabled {
		return false
	}

	sm.revokedTokensMu.RLock()
	_, revoked := sm.revokedTokens[tokenID]
	sm.revokedTokensMu.RUnlock()
	return revoked
}

func (sm *SecurityMiddleware) getRateLimiter(key string) *rate.Limiter {
	sm.rateLimiterMu.RLock()
	limiter, exists := sm.rateLimiters[key]
	sm.rateLimiterMu.RUnlock()

	if !exists {
		sm.rateLimiterMu.Lock()
		if limiter, exists = sm.rateLimiters[key]; !exists {
			limiter = rate.NewLimiter(
				rate.Limit(sm.config.RateLimit.GlobalRequestsPerSec),
				sm.config.RateLimit.GlobalBurstSize,
			)
			sm.rateLimiters[key] = limiter
		}
		sm.rateLimiterMu.Unlock()
	}

	return limiter
}

func (sm *SecurityMiddleware) isIPWhitelisted(ip string) bool {
	for _, whitelistedIP := range sm.config.RateLimit.IPWhitelist {
		if ip == whitelistedIP {
			return true
		}
	}
	return false
}

func (sm *SecurityMiddleware) isIPBlacklisted(ip string) bool {
	for _, blacklistedIP := range sm.config.RateLimit.IPBlacklist {
		if ip == blacklistedIP {
			return true
		}
	}
	return false
}

func (sm *SecurityMiddleware) shouldAuditEvent(path, method string, status int) bool {
	// Always audit authentication events
	if strings.Contains(path, "login") || strings.Contains(path, "auth") {
		return true
	}

	// Audit failed requests
	if status >= 400 {
		return true
	}

	// Audit sensitive operations
	sensitiveOperations := []string{
		"/api/v1/enterprise/policies",
		"/api/v1/enterprise/rbac",
		"/api/v1/enterprise/enforcement",
	}

	for _, op := range sensitiveOperations {
		if strings.HasPrefix(path, op) {
			return true
		}
	}

	return false
}

func (sm *SecurityMiddleware) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		// Cleanup old rate limiters
		sm.rateLimiterMu.Lock()
		for key, limiter := range sm.rateLimiters {
			if limiter.Tokens() == float64(sm.config.RateLimit.GlobalBurstSize) {
				delete(sm.rateLimiters, key)
			}
		}
		sm.rateLimiterMu.Unlock()

		// Cleanup old login attempts
		sm.loginAttemptsMu.Lock()
		for ip, tracker := range sm.loginAttempts {
			if now.Sub(tracker.LastAttempt) > time.Hour {
				delete(sm.loginAttempts, ip)
			}
		}
		sm.loginAttemptsMu.Unlock()

		// Cleanup expired revoked tokens
		sm.revokedTokensMu.Lock()
		for tokenID, revokedAt := range sm.revokedTokens {
			if now.Sub(revokedAt) > 24*time.Hour {
				delete(sm.revokedTokens, tokenID)
			}
		}
		sm.revokedTokensMu.Unlock()
	}
}

// responseWriter wraps gin.ResponseWriter to capture status code
type responseWriter struct {
	gin.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
