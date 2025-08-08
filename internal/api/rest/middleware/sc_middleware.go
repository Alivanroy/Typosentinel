package middleware

import (
	"context"
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
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ratelimit"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// rateLimitEntry stores rate limiting data for a client
type rateLimitEntry struct {
	requests   []time.Time
	lastAccess time.Time
}

// SupplyChainMiddleware provides middleware for supply chain security endpoints
type SupplyChainMiddleware struct {
	config         *config.Config
	logger         *logger.Logger
	rateLimiter    ratelimit.RateLimiter
	rateLimitStore map[string]*rateLimitEntry
	rateLimitMu    sync.RWMutex
}

// NewSupplyChainMiddleware creates a new supply chain middleware instance
func NewSupplyChainMiddleware(cfg *config.Config, log *logger.Logger) *SupplyChainMiddleware {
	// Initialize rate limiter with Redis URL from config or fallback to memory
	var redisURL string
	if cfg.Redis.Enabled && cfg.Redis.Host != "" {
		redisURL = fmt.Sprintf("redis://%s:%d", cfg.Redis.Host, cfg.Redis.Port)
		if cfg.Redis.Password != "" {
			redisURL = fmt.Sprintf("redis://:%s@%s:%d", cfg.Redis.Password, cfg.Redis.Host, cfg.Redis.Port)
		}
	}
	
	rateLimiter := ratelimit.NewFallbackRateLimiter(redisURL)
	
	return &SupplyChainMiddleware{
		config:         cfg,
		logger:         log,
		rateLimiter:    rateLimiter,
		rateLimitStore: make(map[string]*rateLimitEntry),
	}
}

// SupplyChainAuth validates supply chain specific authentication
func (m *SupplyChainMiddleware) SupplyChainAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if supply chain features are enabled
		if m.config.SupplyChain != nil && !m.config.SupplyChain.Enabled {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Supply chain security features are disabled",
				"code":  "SC_DISABLED",
			})
			c.Abort()
			return
		}

		// Enhanced authentication for supply chain endpoints
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Allow unauthenticated access for basic endpoints in development
			if m.isPublicEndpoint(c.Request.URL.Path) {
				c.Next()
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required for supply chain endpoints",
				"code":  "SC_AUTH_REQUIRED",
			})
			c.Abort()
			return
		}

		// Validate token format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authentication format",
				"code":  "SC_INVALID_AUTH",
			})
			c.Abort()
			return
		}

		// Extract and validate token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if !m.validateSupplyChainToken(token) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid or expired supply chain token",
				"code":  "SC_INVALID_TOKEN",
			})
			c.Abort()
			return
		}

		// Set authenticated context
		c.Set("sc_authenticated", true)
		c.Set("sc_token", token)
		c.Next()
	}
}

// cleanupOldEntries removes old rate limit entries to prevent memory leaks
func (m *SupplyChainMiddleware) cleanupOldEntries(now time.Time) {
	m.rateLimitMu.Lock()
	defer m.rateLimitMu.Unlock()
	
	// Clean up entries older than 1 hour
	cutoff := now.Add(-time.Hour)
	
	for key, entry := range m.rateLimitStore {
		if entry.lastAccess.Before(cutoff) {
			delete(m.rateLimitStore, key)
		}
	}
}

// SupplyChainRateLimit implements rate limiting for supply chain endpoints
func (m *SupplyChainMiddleware) SupplyChainRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip rate limiting for public endpoints
		if m.isPublicEndpoint(c.Request.URL.Path) {
			c.Next()
			return
		}
		
		// Get client identifier (IP address or user ID if authenticated)
		clientID := m.getClientIdentifier(c)
		
		// Define rate limits based on endpoint type
		limit, window := m.getRateLimitForEndpoint(c.Request.URL.Path)
		
		// Check rate limit
		ctx := context.Background()
		allowed, err := m.rateLimiter.Allow(ctx, clientID, limit, window)
		if err != nil {
			m.logger.Error("Rate limiter error", map[string]interface{}{
				"error":     err.Error(),
				"client_id": clientID,
				"path":      c.Request.URL.Path,
			})
			// On error, allow the request but log the issue
			c.Next()
			return
		}
		
		if !allowed {
			m.logger.Warn("Rate limit exceeded", map[string]interface{}{
				"client_id": clientID,
				"path":      c.Request.URL.Path,
				"method":    c.Request.Method,
				"limit":     limit,
				"window":    window,
			})
			
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			c.Header("X-RateLimit-Window", window.String())
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"message": fmt.Sprintf("Too many requests. Limit: %d per %s", limit, window),
			})
			c.Abort()
			return
		}
		
		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Window", window.String())
		
		m.logger.Debug("Rate limiting check passed", map[string]interface{}{
			"client_id": clientID,
			"path":      c.Request.URL.Path,
			"method":    c.Request.Method,
			"limit":     limit,
			"window":    window,
		})
		
		c.Next()
	}
}

// SupplyChainLogging logs supply chain specific operations
func (m *SupplyChainMiddleware) SupplyChainLogging() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Process request
		c.Next()

		// Log after processing
		latency := time.Since(start)
		statusCode := c.Writer.Status()

		// Enhanced logging for supply chain operations
		logFields := map[string]interface{}{
			"component":    "supply_chain",
			"method":       method,
			"path":         path,
			"status_code":  statusCode,
			"latency_ms":   latency.Milliseconds(),
			"client_ip":    clientIP,
			"user_agent":   userAgent,
			"timestamp":    time.Now().UTC(),
		}

		// Add authentication info if available
		if authenticated, exists := c.Get("sc_authenticated"); exists && authenticated.(bool) {
			logFields["authenticated"] = true
		}

		// Add error info for failed requests
		if statusCode >= 400 {
			if errors, exists := c.Get("errors"); exists {
				logFields["errors"] = errors
			}
		}

		// Log based on status code
		if statusCode >= 500 {
			m.logger.Error("Supply chain operation failed", logFields)
		} else if statusCode >= 400 {
			m.logger.Warn("Supply chain operation warning", logFields)
		} else {
			m.logger.Info("Supply chain operation completed", logFields)
		}
	}
}

// SupplyChainHeaders adds security headers for supply chain endpoints
func (m *SupplyChainMiddleware) SupplyChainHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Supply chain specific headers
		c.Header("X-SC-Version", "1.0")
		c.Header("X-SC-Features", "build-integrity,threat-intel,graph-analysis")

		c.Next()
	}
}

// Helper methods

// getClientIdentifier returns a unique identifier for the client
func (m *SupplyChainMiddleware) getClientIdentifier(c *gin.Context) string {
	// Try to get user ID from authentication context first
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("user:%s", userID)
	}
	
	// Fall back to IP address
	return fmt.Sprintf("ip:%s", c.ClientIP())
}

// getRateLimitForEndpoint returns the rate limit and window for a specific endpoint
func (m *SupplyChainMiddleware) getRateLimitForEndpoint(path string) (int, time.Duration) {
	// High-cost endpoints have stricter limits
	if m.isHighCostEndpoint(path) {
		return 5, time.Minute // 5 requests per minute
	}
	
	// Scan endpoints
	if strings.Contains(path, "/scan") {
		return 10, time.Minute // 10 scans per minute
	}
	
	// Analysis endpoints
	if strings.Contains(path, "/analyze") {
		return 15, time.Minute // 15 analyses per minute
	}
	
	// Default rate limit for other endpoints
	return 100, time.Minute // 100 requests per minute
}

// isPublicEndpoint checks if an endpoint allows unauthenticated access
func (m *SupplyChainMiddleware) isPublicEndpoint(path string) bool {
	publicEndpoints := []string{
		"/v1/supply-chain/health",
		"/v1/supply-chain/status",
		"/v1/supply-chain/version",
	}

	for _, endpoint := range publicEndpoints {
		if strings.HasPrefix(path, endpoint) {
			return true
		}
	}
	return false
}

// isHighCostEndpoint checks if an endpoint is computationally expensive
func (m *SupplyChainMiddleware) isHighCostEndpoint(path string) bool {
	highCostEndpoints := []string{
		"/v1/supply-chain/scan",
		"/v1/supply-chain/graph/analyze",
		"/v1/supply-chain/threats/intel",
	}

	for _, endpoint := range highCostEndpoints {
		if strings.HasPrefix(path, endpoint) {
			return true
		}
	}
	return false
}

// validateSupplyChainToken validates the supply chain authentication token
func (m *SupplyChainMiddleware) validateSupplyChainToken(token string) bool {
	// Validate JWT-like token
	claims, err := m.validateJWTLikeToken(token)
	if err != nil {
		m.logger.Warn("Token validation failed", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Check token expiration
	if claims.ExpiresAt > 0 && claims.ExpiresAt < time.Now().Unix() {
		m.logger.Warn("Token expired", map[string]interface{}{
			"expires_at": time.Unix(claims.ExpiresAt, 0),
		})
		return false
	}

	// Check if token is revoked (check against revocation list)
	if m.isTokenRevoked(claims.ID) {
		m.logger.Warn("Token revoked", map[string]interface{}{
			"token_id": claims.ID,
		})
		return false
	}

	return true
}

// TokenClaims represents token claims
type TokenClaims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	ID        string `json:"jti"`
}

// validateJWTLikeToken validates and parses a JWT-like token
func (m *SupplyChainMiddleware) validateJWTLikeToken(tokenString string) (*TokenClaims, error) {
	// Get JWT secret from config
	jwtSecret := m.config.Security.JWT.Secret
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT secret not configured")
	}

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

	// Verify signature
	expectedSignature := m.generateTokenSignature(parts[0], parts[1], jwtSecret)
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid token signature")
	}

	return &claims, nil
}

// generateTokenSignature generates HMAC signature for token
func (m *SupplyChainMiddleware) generateTokenSignature(header, payload, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(header + "." + payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// isTokenRevoked checks if a token is in the revocation list
func (m *SupplyChainMiddleware) isTokenRevoked(tokenID string) bool {
	// In production, this would check against a Redis cache or database
	// Check against revocation list (this would be stored in Redis/DB in production)
	revokedTokens := m.getRevokedTokens()
	for _, revokedID := range revokedTokens {
		if tokenID == revokedID {
			return true
		}
	}

	return false
}

// getRevokedTokens retrieves the list of revoked token IDs
func (m *SupplyChainMiddleware) getRevokedTokens() []string {
	// In production, this would fetch from Redis or database
	// For now, return empty list
	return []string{}
}

// checkRateLimit checks if the client has exceeded rate limits
func (m *SupplyChainMiddleware) checkRateLimit(clientIP, limitType string, maxRequests int, window time.Duration) bool {
	// Use a simple in-memory sliding window rate limiter
	key := fmt.Sprintf("%s:%s", clientIP, limitType)
	now := time.Now()
	
	// Clean up old entries periodically
	m.cleanupOldEntries(now)
	
	m.rateLimitMu.Lock()
	defer m.rateLimitMu.Unlock()
	
	// Get or create rate limit entry
	if entry, exists := m.rateLimitStore[key]; exists {
		// Filter out requests outside the current window
		var validRequests []time.Time
		cutoff := now.Add(-window)
		
		for _, reqTime := range entry.requests {
			if reqTime.After(cutoff) {
				validRequests = append(validRequests, reqTime)
			}
		}
		
		// Check if we're within limits
		if len(validRequests) >= maxRequests {
			return false
		}
		
		// Add current request
		validRequests = append(validRequests, now)
		entry.requests = validRequests
		entry.lastAccess = now
	} else {
		// First request for this key
		m.rateLimitStore[key] = &rateLimitEntry{
			requests:   []time.Time{now},
			lastAccess: now,
		}
	}
	
	return true
}

// SupplyChainCORS handles CORS for supply chain endpoints
func (m *SupplyChainMiddleware) SupplyChainCORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Allow specific origins for supply chain endpoints
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:8080",
			"https://typosentinel.example.com",
		}

		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				c.Header("Access-Control-Allow-Origin", origin)
				break
			}
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-SC-Token")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}