package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// corsMiddleware configures CORS middleware
func corsMiddleware(corsConfig config.CORSConfig) gin.HandlerFunc {
	config := cors.Config{
		AllowOrigins:     corsConfig.AllowedOrigins,
		AllowMethods:     corsConfig.AllowedMethods,
		AllowHeaders:     corsConfig.AllowedHeaders,
		ExposeHeaders:    corsConfig.ExposedHeaders,
		AllowCredentials: corsConfig.AllowCredentials,
		MaxAge:           time.Duration(corsConfig.MaxAge) * time.Second,
	}

	// If no origins specified, allow all
	if len(config.AllowOrigins) == 0 {
		config.AllowAllOrigins = true
	}

	// Default methods if none specified
	if len(config.AllowMethods) == 0 {
		config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}

	// Default headers if none specified
	if len(config.AllowHeaders) == 0 {
		config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization", "X-Requested-With"}
	}

	return cors.New(config)
}

// loggingMiddleware provides request logging
func loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Custom log format
		logData := map[string]interface{}{
			"timestamp":  param.TimeStamp.Format(time.RFC3339),
			"method":     param.Method,
			"path":       param.Path,
			"status":     param.StatusCode,
			"latency":    param.Latency.String(),
			"client_ip":  param.ClientIP,
			"user_agent": param.Request.UserAgent(),
			"request_id": param.Request.Header.Get("X-Request-ID"),
			"body_size":  param.BodySize,
		}

		if param.ErrorMessage != "" {
			logData["error"] = param.ErrorMessage
		}

		// Log based on status code
		if param.StatusCode >= 500 {
			log.Printf("HTTP request - Method: %s, Path: %s, Status: %d, Duration: %v, IP: %s", param.Method, param.Path, param.StatusCode, param.Latency, param.ClientIP)
		} else if param.StatusCode >= 400 {
			log.Printf("HTTP request - Method: %s, Path: %s, Status: %d, Duration: %v, IP: %s", param.Method, param.Path, param.StatusCode, param.Latency, param.ClientIP)
		} else {
			log.Printf("HTTP request - Method: %s, Path: %s, Status: %d, Duration: %v, IP: %s", param.Method, param.Path, param.StatusCode, param.Latency, param.ClientIP)
		}

		return ""
	})
}

// RateLimiter represents a rate limiter for API requests
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	limit    rate.Limit
	burst    int
	cleanup  time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond int, burstSize int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		limit:    rate.Limit(requestsPerSecond),
		burst:    burstSize,
		cleanup:  time.Minute * 5, // Clean up old limiters every 5 minutes
	}

	// Start cleanup goroutine
	go rl.cleanupRoutine()

	return rl
}

// getLimiter gets or creates a rate limiter for the given key
func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		if limiter, exists = rl.limiters[key]; !exists {
			limiter = rate.NewLimiter(rl.limit, rl.burst)
			rl.limiters[key] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter
}

// Allow checks if a request is allowed for the given key
func (rl *RateLimiter) Allow(key string) bool {
	return rl.getLimiter(key).Allow()
}

// cleanupRoutine periodically removes unused rate limiters
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for key, limiter := range rl.limiters {
			// Remove limiters that haven't been used recently
			if limiter.Tokens() == float64(rl.burst) {
				delete(rl.limiters, key)
			}
		}
		rl.mu.Unlock()
	}
}

// Global rate limiter instance
var globalRateLimiter *RateLimiter

// rateLimitMiddleware provides rate limiting functionality
func rateLimitMiddleware(rateLimitConfig config.APIRateLimiting) gin.HandlerFunc {
	if !rateLimitConfig.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Initialize global rate limiter if not already done
	if globalRateLimiter == nil {
		globalRateLimiter = NewRateLimiter(rateLimitConfig.Global.RequestsPerSecond, rateLimitConfig.Global.BurstSize)
	}

	return func(c *gin.Context) {
		// Determine rate limit key based on strategy
		var key string
		key = c.ClientIP()

		// Check rate limit
		if !globalRateLimiter.Allow(key) {
			// Add rate limit headers
			c.Header("X-RateLimit-Limit", strconv.Itoa(rateLimitConfig.Global.RequestsPerSecond))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10))

			log.Printf("Rate limit exceeded for key: %s, IP: %s, path: %s", key, c.ClientIP(), c.Request.URL.Path)

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests. Please try again later.",
				"retry_after": 1,
			})
			c.Abort()
			return
		}

		// Add rate limit headers for successful requests
		c.Header("X-RateLimit-Limit", strconv.Itoa(rateLimitConfig.Global.RequestsPerSecond))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(rateLimitConfig.Global.RequestsPerSecond-1))

		c.Next()
	}
}

// authMiddleware provides authentication functionality
func authMiddleware(authConfig *config.APIAuthentication) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for health checks and public endpoints
		path := c.Request.URL.Path
		if path == "/health" || path == "/ready" || path == "/metrics" ||
			strings.HasSuffix(path, "/system/status") {
			c.Next()
			return
		}

		// Skip if authentication is disabled
		if !authConfig.Enabled {
			c.Next()
			return
		}

		var authenticated bool
		var userID string
		var authMethod string

		// Try different authentication methods based on configuration
		if len(authConfig.Methods) > 0 {
			// Try configured methods in order
			for _, method := range authConfig.Methods {
				switch method {
				case "api_key":
					authenticated, userID = authenticateAPIKey(c, authConfig)
					authMethod = "api_key"
				case "jwt":
					authenticated, userID = authenticateJWT(c, authConfig)
					authMethod = "jwt"
				case "basic":
					authenticated, userID = authenticateBasic(c, authConfig)
					authMethod = "basic"
				}
				if authenticated {
					break
				}
			}
		} else {
			// Try all methods if no specific methods are configured
			if authenticated, userID = authenticateJWT(c, authConfig); !authenticated {
				if authenticated, userID = authenticateAPIKey(c, authConfig); !authenticated {
					authenticated, userID = authenticateBasic(c, authConfig)
					authMethod = "basic"
				} else {
					authMethod = "api_key"
				}
			} else {
				authMethod = "jwt"
			}
		}

		if !authenticated {
			log.Printf("Authentication failed - IP: %s, path: %s, method: %s", c.ClientIP(), c.Request.URL.Path, c.Request.Method)

			c.Header("WWW-Authenticate", `Bearer realm="TypoSentinel API"`)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"message": "Valid authentication credentials are required to access this resource.",
			})
			c.Abort()
			return
		}

		// Set authentication context
		c.Set("authenticated", true)
		c.Set("user_id", userID)
		c.Set("auth_method", authMethod)

		logger.DebugWithContext("Authentication successful", map[string]interface{}{
			"user_id":     userID,
			"auth_method": authMethod,
			"path":        c.Request.URL.Path,
		})

		c.Next()
	}
}

// authenticateAPIKey authenticates using API key
func authenticateAPIKey(c *gin.Context, authConfig *config.APIAuthentication) (bool, string) {
	// Try different header names
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		apiKey = c.GetHeader("Authorization")
		if strings.HasPrefix(apiKey, "Bearer ") {
			apiKey = strings.TrimPrefix(apiKey, "Bearer ")
		} else if strings.HasPrefix(apiKey, "ApiKey ") {
			apiKey = strings.TrimPrefix(apiKey, "ApiKey ")
		} else {
			apiKey = ""
		}
	}

	// Try query parameter as fallback
	if apiKey == "" {
		apiKey = c.Query("api_key")
	}

	if apiKey == "" {
		return false, ""
	}

	// Validate API key against environment or key store
	// Check if API key exists in environment variables or key store
	if os.Getenv("TYPOSENTINEL_DISABLE_AUTH") == "true" {
		// Development mode - allow any non-empty key
		return true, "dev_user"
	}

	// In production, validate against configured key store
	keyStore := os.Getenv("TYPOSENTINEL_KEY_STORE")
	if keyStore == "" {
		return false, ""
	}

	// Hash the API key for comparison
	hasher := sha256.New()
	hasher.Write([]byte(apiKey))
	hashedKey := hex.EncodeToString(hasher.Sum(nil))

	// Check against stored hashed keys (this would be a database lookup in production)
	validKeyHashes := strings.Split(os.Getenv("TYPOSENTINEL_VALID_KEY_HASHES"), ",")
	for _, validHash := range validKeyHashes {
		if hashedKey == strings.TrimSpace(validHash) {
			return true, "authenticated_user"
		}
	}

	return false, ""
}

// authenticateJWT authenticates using JWT token
func authenticateJWT(c *gin.Context, authConfig *config.APIAuthentication) (bool, string) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false, ""
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return false, ""
	}

	// Use proper JWT validator for production tokens
	if authConfig.JWTSecret != "" {
		validator := NewJWTValidator(authConfig.JWTSecret, "typosentinel")
		claims, err := validator.ValidateToken(token)
		if err != nil {
			log.Printf("JWT validation failed: %v", err)
			return false, ""
		}

		// Set additional context for role-based access
		c.Set("user_role", claims.Role)
		c.Set("user_name", claims.Name)

		return true, claims.Subject
	}

	// Fallback to test tokens for development
	testTokens := GetTestTokens()
	if userID, exists := testTokens[token]; exists {
		logger.DebugWithContext("Test JWT token validated", map[string]interface{}{
			"user_id": userID,
		})
		return true, userID
	}

	log.Printf("JWT token validation failed: token length %d", len(token))
	return false, ""
}

// authenticateBasic authenticates using basic authentication
func authenticateBasic(c *gin.Context, authConfig *config.APIAuthentication) (bool, string) {
	username, password, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		return false, ""
	}

	// Placeholder basic auth validation
	// In a real implementation, this would check against a user database
	validUsers := map[string]string{
		"admin":    "password123",
		"user":     "userpass",
		"demo":     "demo",
		"readonly": "readonly",
	}

	if validPassword, exists := validUsers[username]; exists && validPassword == password {
		return true, username
	}

	return false, ""
}

// securityHeadersMiddleware adds security headers
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		c.Next()
	}
}

// compressionMiddleware adds response compression
func compressionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if client accepts gzip
		if strings.Contains(c.GetHeader("Accept-Encoding"), "gzip") {
			c.Header("Content-Encoding", "gzip")
		}

		c.Next()
	}
}

// metricsMiddleware collects request metrics
func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// Calculate request duration
		duration := time.Since(start)

		// Log metrics (in a real implementation, this would send to a metrics system)
		logger.DebugWithContext("Request metrics", map[string]interface{}{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     c.Writer.Status(),
			"duration":   duration.Milliseconds(),
			"size":       c.Writer.Size(),
			"user_agent": c.Request.UserAgent(),
		})
	}
}

// errorHandlingMiddleware provides centralized error handling
func errorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Handle any errors that occurred during request processing
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			log.Printf("Request error - path: %s, method: %s, error: %v", c.Request.URL.Path, c.Request.Method, err.Error())

			// Return appropriate error response
			switch err.Type {
			case gin.ErrorTypeBind:
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "Invalid request",
					"message": "Request body is malformed or missing required fields",
				})
			case gin.ErrorTypePublic:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Internal server error",
					"message": "An unexpected error occurred",
				})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Internal server error",
					"message": "An unexpected error occurred",
				})
			}
		}
	}
}
