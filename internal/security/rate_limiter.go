package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"
)

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	redis       *redis.Client
	localLimits map[string]*rate.Limiter
	mutex       sync.RWMutex
	config      *RateLimitConfig
}

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	// Global limits
	GlobalRequestsPerSecond int           `yaml:"global_requests_per_second" default:"1000"`
	GlobalBurstSize         int           `yaml:"global_burst_size" default:"2000"`
	GlobalWindowDuration    time.Duration `yaml:"global_window_duration" default:"1m"`

	// Per-IP limits
	IPRequestsPerSecond int           `yaml:"ip_requests_per_second" default:"10"`
	IPBurstSize         int           `yaml:"ip_burst_size" default:"20"`
	IPWindowDuration    time.Duration `yaml:"ip_window_duration" default:"1m"`

	// Per-User limits
	UserRequestsPerSecond int           `yaml:"user_requests_per_second" default:"50"`
	UserBurstSize         int           `yaml:"user_burst_size" default:"100"`
	UserWindowDuration    time.Duration `yaml:"user_window_duration" default:"1m"`

	// Per-API-Key limits
	APIKeyRequestsPerSecond int           `yaml:"api_key_requests_per_second" default:"100"`
	APIKeyBurstSize         int           `yaml:"api_key_burst_size" default:"200"`
	APIKeyWindowDuration    time.Duration `yaml:"api_key_window_duration" default:"1m"`

	// Endpoint-specific limits
	EndpointLimits map[string]EndpointLimit `yaml:"endpoint_limits"`

	// Advanced settings
	EnableDistributed bool          `yaml:"enable_distributed" default:"false"`
	CleanupInterval   time.Duration `yaml:"cleanup_interval" default:"5m"`
	MaxMemoryUsage    int64         `yaml:"max_memory_usage" default:"100000000"` // 100MB
	
	// Whitelist/Blacklist
	WhitelistedIPs []string `yaml:"whitelisted_ips"`
	BlacklistedIPs []string `yaml:"blacklisted_ips"`
	
	// Adaptive rate limiting
	EnableAdaptive     bool    `yaml:"enable_adaptive" default:"false"`
	AdaptiveThreshold  float64 `yaml:"adaptive_threshold" default:"0.8"`
	AdaptiveMultiplier float64 `yaml:"adaptive_multiplier" default:"0.5"`
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed       bool          `json:"allowed"`
	Limit         int           `json:"limit"`
	Remaining     int           `json:"remaining"`
	ResetTime     time.Time     `json:"reset_time"`
	RetryAfter    time.Duration `json:"retry_after,omitempty"`
	LimitType     string        `json:"limit_type"`
	Identifier    string        `json:"identifier"`
}

// RateLimitType represents different types of rate limits
type RateLimitType string

const (
	RateLimitTypeGlobal   RateLimitType = "global"
	RateLimitTypeIP       RateLimitType = "ip"
	RateLimitTypeUser     RateLimitType = "user"
	RateLimitTypeAPIKey   RateLimitType = "api_key"
	RateLimitTypeEndpoint RateLimitType = "endpoint"
)

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimitConfig, redisClient *redis.Client) *RateLimiter {
	rl := &RateLimiter{
		redis:       redisClient,
		localLimits: make(map[string]*rate.Limiter),
		config:      config,
	}

	// Start cleanup routine
	go rl.cleanupRoutine()

	return rl
}

// CheckRateLimit checks if a request should be allowed
func (rl *RateLimiter) CheckRateLimit(ctx context.Context, req *http.Request, userID, apiKey string) (*RateLimitResult, error) {
	clientIP := rl.getClientIP(req)
	
	// Check blacklist first
	if rl.isBlacklisted(clientIP) {
		return &RateLimitResult{
			Allowed:    false,
			LimitType:  string(RateLimitTypeIP),
			Identifier: clientIP,
			RetryAfter: time.Hour, // Long retry for blacklisted IPs
		}, nil
	}

	// Check whitelist
	if rl.isWhitelisted(clientIP) {
		return &RateLimitResult{
			Allowed:    true,
			LimitType:  "whitelisted",
			Identifier: clientIP,
		}, nil
	}

	// Check multiple rate limits in order of priority
	checks := []struct {
		limitType  RateLimitType
		identifier string
		limit      int
		burst      int
		window     time.Duration
	}{
		{RateLimitTypeGlobal, "global", rl.config.GlobalRequestsPerSecond, rl.config.GlobalBurstSize, rl.config.GlobalWindowDuration},
		{RateLimitTypeIP, clientIP, rl.config.IPRequestsPerSecond, rl.config.IPBurstSize, rl.config.IPWindowDuration},
	}

	// Add user-specific limit if user is authenticated
	if userID != "" {
		checks = append(checks, struct {
			limitType  RateLimitType
			identifier string
			limit      int
			burst      int
			window     time.Duration
		}{RateLimitTypeUser, fmt.Sprintf("user:%s", userID), rl.config.UserRequestsPerSecond, rl.config.UserBurstSize, rl.config.UserWindowDuration})
	}

	// Add API key-specific limit if API key is provided
	if apiKey != "" {
		checks = append(checks, struct {
			limitType  RateLimitType
			identifier string
			limit      int
			burst      int
			window     time.Duration
		}{RateLimitTypeAPIKey, fmt.Sprintf("apikey:%s", apiKey), rl.config.APIKeyRequestsPerSecond, rl.config.APIKeyBurstSize, rl.config.APIKeyWindowDuration})
	}

	// Check endpoint-specific limits
	endpoint := rl.getEndpointKey(req)
	if endpointLimit, exists := rl.config.EndpointLimits[endpoint]; exists {
		checks = append(checks, struct {
			limitType  RateLimitType
			identifier string
			limit      int
			burst      int
			window     time.Duration
		}{RateLimitTypeEndpoint, fmt.Sprintf("endpoint:%s:%s", endpoint, clientIP), endpointLimit.RequestsPerSecond, endpointLimit.BurstSize, endpointLimit.WindowDuration})
	}

	// Check each rate limit
	for _, check := range checks {
		result, err := rl.checkLimit(ctx, check.limitType, check.identifier, check.limit, check.burst, check.window)
		if err != nil {
			return nil, err
		}
		
		if !result.Allowed {
			return result, nil
		}
	}

	// All checks passed
	return &RateLimitResult{
		Allowed:    true,
		LimitType:  "allowed",
		Identifier: clientIP,
	}, nil
}

// checkLimit performs the actual rate limit check
func (rl *RateLimiter) checkLimit(ctx context.Context, limitType RateLimitType, identifier string, limit, burst int, window time.Duration) (*RateLimitResult, error) {
	if rl.config.EnableDistributed && rl.redis != nil {
		return rl.checkDistributedLimit(ctx, limitType, identifier, limit, burst, window)
	}
	return rl.checkLocalLimit(limitType, identifier, limit, burst)
}

// checkLocalLimit checks rate limit using local memory
func (rl *RateLimiter) checkLocalLimit(limitType RateLimitType, identifier string, limit, burst int) (*RateLimitResult, error) {
	key := fmt.Sprintf("%s:%s", limitType, identifier)
	
	rl.mutex.Lock()
	limiter, exists := rl.localLimits[key]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(limit), burst)
		rl.localLimits[key] = limiter
	}
	rl.mutex.Unlock()

	now := time.Now()
	reservation := limiter.ReserveN(now, 1)
	
	if !reservation.OK() {
		return &RateLimitResult{
			Allowed:    false,
			Limit:      limit,
			Remaining:  0,
			ResetTime:  now.Add(time.Second),
			RetryAfter: time.Second,
			LimitType:  string(limitType),
			Identifier: identifier,
		}, nil
	}

	delay := reservation.DelayFrom(now)
	if delay > 0 {
		reservation.Cancel()
		return &RateLimitResult{
			Allowed:    false,
			Limit:      limit,
			Remaining:  0,
			ResetTime:  now.Add(delay),
			RetryAfter: delay,
			LimitType:  string(limitType),
			Identifier: identifier,
		}, nil
	}

	// Calculate remaining tokens (approximate)
	remaining := burst - 1
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitResult{
		Allowed:    true,
		Limit:      limit,
		Remaining:  remaining,
		ResetTime:  now.Add(time.Second),
		LimitType:  string(limitType),
		Identifier: identifier,
	}, nil
}

// checkDistributedLimit checks rate limit using Redis
func (rl *RateLimiter) checkDistributedLimit(ctx context.Context, limitType RateLimitType, identifier string, limit, burst int, window time.Duration) (*RateLimitResult, error) {
	key := fmt.Sprintf("ratelimit:%s:%s", limitType, identifier)
	now := time.Now()
	windowStart := now.Truncate(window)
	
	// Sliding window log implementation
	script := `
		local key = KEYS[1]
		local window_start = tonumber(ARGV[1])
		local window_size = tonumber(ARGV[2])
		local limit = tonumber(ARGV[3])
		local now = tonumber(ARGV[4])
		
		-- Remove old entries
		redis.call('ZREMRANGEBYSCORE', key, 0, window_start - window_size)
		
		-- Count current requests
		local current = redis.call('ZCARD', key)
		
		if current < limit then
			-- Add current request
			redis.call('ZADD', key, now, now)
			redis.call('EXPIRE', key, window_size)
			return {1, limit - current - 1, window_start + window_size}
		else
			-- Rate limit exceeded
			local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
			local reset_time = window_start + window_size
			if #oldest > 0 then
				reset_time = tonumber(oldest[2]) + window_size
			end
			return {0, 0, reset_time}
		end
	`
	
	result, err := rl.redis.Eval(ctx, script, []string{key}, 
		windowStart.Unix(), 
		int64(window.Seconds()), 
		limit, 
		now.Unix()).Result()
	
	if err != nil {
		return nil, fmt.Errorf("redis rate limit check failed: %w", err)
	}
	
	resultSlice := result.([]interface{})
	allowed := resultSlice[0].(int64) == 1
	remaining := int(resultSlice[1].(int64))
	resetTime := time.Unix(resultSlice[2].(int64), 0)
	
	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Until(resetTime)
		if retryAfter < 0 {
			retryAfter = 0
		}
	}
	
	return &RateLimitResult{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		ResetTime:  resetTime,
		RetryAfter: retryAfter,
		LimitType:  string(limitType),
		Identifier: identifier,
	}, nil
}

// getClientIP extracts the client IP from the request
func (rl *RateLimiter) getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	
	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	
	return ip
}

// getEndpointKey generates a key for endpoint-specific rate limiting
func (rl *RateLimiter) getEndpointKey(req *http.Request) string {
	return fmt.Sprintf("%s:%s", req.Method, req.URL.Path)
}

// isWhitelisted checks if an IP is whitelisted
func (rl *RateLimiter) isWhitelisted(ip string) bool {
	for _, whitelistedIP := range rl.config.WhitelistedIPs {
		if ip == whitelistedIP {
			return true
		}
		
		// Check CIDR ranges
		if strings.Contains(whitelistedIP, "/") {
			_, network, err := net.ParseCIDR(whitelistedIP)
			if err == nil && network.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

// isBlacklisted checks if an IP is blacklisted
func (rl *RateLimiter) isBlacklisted(ip string) bool {
	for _, blacklistedIP := range rl.config.BlacklistedIPs {
		if ip == blacklistedIP {
			return true
		}
		
		// Check CIDR ranges
		if strings.Contains(blacklistedIP, "/") {
			_, network, err := net.ParseCIDR(blacklistedIP)
			if err == nil && network.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

// cleanupRoutine periodically cleans up old rate limit entries
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup removes old rate limit entries to prevent memory leaks
func (rl *RateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	// Simple cleanup: remove entries if we have too many
	if len(rl.localLimits) > 10000 {
		// Keep only the most recent 5000 entries
		newLimits := make(map[string]*rate.Limiter)
		count := 0
		for key, limiter := range rl.localLimits {
			if count < 5000 {
				newLimits[key] = limiter
				count++
			}
		}
		rl.localLimits = newLimits
	}
}

// RateLimitMiddleware returns an HTTP middleware for rate limiting
func (rl *RateLimiter) RateLimitMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			
			// Extract user ID and API key from request
			userID := r.Header.Get("X-User-ID")
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				apiKey = r.Header.Get("Authorization")
				if strings.HasPrefix(apiKey, "Bearer ") {
					apiKey = strings.TrimPrefix(apiKey, "Bearer ")
				}
			}
			
			result, err := rl.CheckRateLimit(ctx, r, userID, apiKey)
			if err != nil {
				http.Error(w, "Rate limit check failed", http.StatusInternalServerError)
				return
			}
			
			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
			
			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// GetStats returns rate limiting statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()
	
	stats := map[string]interface{}{
		"local_limiters_count": len(rl.localLimits),
		"distributed_enabled":  rl.config.EnableDistributed,
		"cleanup_interval":     rl.config.CleanupInterval.String(),
	}
	
	// Add Redis stats if available
	if rl.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if info, err := rl.redis.Info(ctx, "memory").Result(); err == nil {
			stats["redis_memory_info"] = info
		}
	}
	
	return stats
}

// UpdateConfig updates the rate limiter configuration
func (rl *RateLimiter) UpdateConfig(config *RateLimitConfig) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	rl.config = config
	
	// Clear local limiters to apply new limits
	rl.localLimits = make(map[string]*rate.Limiter)
}