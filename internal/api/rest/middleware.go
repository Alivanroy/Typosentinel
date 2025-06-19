package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"golang.org/x/time/rate"

	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/logger"
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
			"timestamp":    param.TimeStamp.Format(time.RFC3339),
			"method":       param.Method,
			"path":         param.Path,
			"status":       param.StatusCode,
			"latency":      param.Latency.String(),
			"client_ip":    param.ClientIP,
			"user_agent":   param.Request.UserAgent(),
			"request_id":   param.Request.Header.Get("X-Request-ID"),
			"body_size":    param.BodySize,
		}

		if param.ErrorMessage != "" {
			logData["error"] = param.ErrorMessage
		}

		// Log based on status code
		if param.StatusCode >= 500 {
			logger.ErrorWithContext("HTTP request", logData)
		} else if param.StatusCode >= 400 {
			logger.WarnWithContext("HTTP request", logData)
		} else {
			logger.InfoWithContext("HTTP request", logData)
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
func NewRateLimiter(requestsPerSecond float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		limit:    rate.Limit(requestsPerSecond),
		burst:    burst,
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
func rateLimitMiddleware(rateLimitConfig config.RateLimitConfig) gin.HandlerFunc {
	if !rateLimitConfig.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	// Initialize global rate limiter if not already done
	if globalRateLimiter == nil {
		globalRateLimiter = NewRateLimiter(
			float64(rateLimitConfig.RequestsPerSecond),
			rateLimitConfig.Burst,
		)
	}

	return func(c *gin.Context) {
		// Determine rate limit key based on strategy
		var key string
		switch rateLimitConfig.Strategy {
		case "ip":
			key = c.ClientIP()
		case "user":
			// Extract user ID from authentication context
			if userID, exists := c.Get("user_id"); exists {
				key = fmt.Sprintf("user:%v", userID)
			} else {
				key = c.ClientIP() // Fallback to IP
			}
		case "api_key":
			// Extract API key
			if apiKey := c.GetHeader("X-API-Key"); apiKey != "" {
				key = fmt.Sprintf("api_key:%s", apiKey)
			} else {
				key = c.ClientIP() // Fallback to IP
			}
		default:
			key = c.ClientIP()
		}

		// Check rate limit
		if !globalRateLimiter.Allow(key) {
			// Add rate limit headers
			c.Header("X-RateLimit-Limit", strconv.Itoa(rateLimitConfig.RequestsPerSecond))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10))

			logger.WarnWithContext("Rate limit exceeded", map[string]interface{}{
				"key":        key,
				"client_ip":  c.ClientIP(),
				"user_agent": c.Request.UserAgent(),
				"path":       c.Request.URL.Path,
			})

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests. Please try again later.",
				"retry_after": 1,
			})
			c.Abort()
			return
		}

		// Add rate limit headers for successful requests
		c.Header("X-RateLimit-Limit", strconv.Itoa(rateLimitConfig.RequestsPerSecond))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(rateLimitConfig.RequestsPerSecond-1))

		c.Next()
	}
}

// authMiddleware provides authentication functionality
func authMiddleware(authConfig config.AuthenticationConfig) gin.HandlerFunc {
	if !authConfig.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		// Skip authentication for health checks and documentation
		path := c.Request.URL.Path
		if path == "/health" || path == "/ready" || strings.HasPrefix(path, "/docs") {
			c.Next()
			return
		}

		var authenticated bool
		var userID string
		var authMethod string

		// Try different authentication methods
		switch authConfig.Type {
		case "api_key":
			authenticated, userID = authenticateAPIKey(c, authConfig)
			authMethod = "api_key"
		case "jwt":
			authenticated, userID = authenticateJWT(c, authConfig)
			authMethod = "jwt"
		case "basic":
			authenticated, userID = authenticateBasic(c, authConfig)
			authMethod = "basic"
		default:
			// Try multiple methods
			if authenticated, userID = authenticateAPIKey(c, authConfig); authenticated {
				authMethod = "api_key"
			} else if authenticated, userID = authenticateJWT(c, authConfig); authenticated {
				authMethod = "jwt"
			} else if authenticated, userID = authenticateBasic(c, authConfig); authenticated {
				authMethod = "basic"
			}
		}

		if !authenticated {
			logger.WarnWithContext("Authentication failed", map[string]interface{}{
				"client_ip":  c.ClientIP(),
				"user_agent": c.Request.UserAgent(),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
			})

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
func authenticateAPIKey(c *gin.Context, authConfig config.AuthenticationConfig) (bool, string) {
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

	// Validate API key (placeholder implementation)
	// In a real implementation, this would check against a database or key store
	validKeys := map[string]string{
		"test-api-key-123":     "user1",
		"demo-key-456":        "demo_user",
		"admin-key-789":       "admin",
		"development-key-000": "dev_user",
	}

	if userID, exists := validKeys[apiKey]; exists {
		return true, userID
	}

	return false, ""
}

// authenticateJWT authenticates using JWT token
func authenticateJWT(c *gin.Context, authConfig config.AuthenticationConfig) (bool, string) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false, ""
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return false, ""
	}

	// Placeholder JWT validation
	// In a real implementation, this would validate the JWT signature and claims
	if token == "valid-jwt-token" {
		return true, "jwt_user"
	}

	return false, ""
}

// authenticateBasic authenticates using basic authentication
func authenticateBasic(c *gin.Context, authConfig config.AuthenticationConfig) (bool, string) {
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
			logger.ErrorWithContext("Request error", map[string]interface{}{
				"error":      err.Error(),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
				"client_ip":  c.ClientIP(),
				"user_agent": c.Request.UserAgent(),
			})

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