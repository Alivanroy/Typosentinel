package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// SupplyChainMiddleware provides middleware for supply chain security endpoints
type SupplyChainMiddleware struct {
	config *config.Config
	logger *logger.Logger
}

// NewSupplyChainMiddleware creates a new supply chain middleware instance
func NewSupplyChainMiddleware(cfg *config.Config, log *logger.Logger) *SupplyChainMiddleware {
	return &SupplyChainMiddleware{
		config: cfg,
		logger: log,
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

// SupplyChainRateLimit implements rate limiting for supply chain endpoints
func (m *SupplyChainMiddleware) SupplyChainRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		endpoint := c.Request.URL.Path

		// Check rate limits based on endpoint type
		if m.isHighCostEndpoint(endpoint) {
			if !m.checkRateLimit(clientIP, "high_cost", 5, time.Minute) {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded for high-cost supply chain operations",
					"code":  "SC_RATE_LIMIT_HIGH",
					"retry_after": 60,
				})
				c.Abort()
				return
			}
		} else {
			if !m.checkRateLimit(clientIP, "standard", 30, time.Minute) {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded for supply chain operations",
					"code":  "SC_RATE_LIMIT_STANDARD",
					"retry_after": 60,
				})
				c.Abort()
				return
			}
		}

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
	// In a real implementation, this would validate against a token store
	// For now, we'll accept any non-empty token
	if len(token) < 10 {
		return false
	}

	// Basic token validation
	// In production, this should validate JWT tokens or API keys
	return true
}

// checkRateLimit checks if the client has exceeded rate limits
func (m *SupplyChainMiddleware) checkRateLimit(clientIP, limitType string, maxRequests int, window time.Duration) bool {
	// In a real implementation, this would use Redis or another store
	// For now, we'll always allow requests
	// TODO: Implement proper rate limiting with Redis/memory store
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