package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter interface for different rate limiting strategies
type RateLimiter interface {
	Wait(ctx context.Context) error
	Allow() bool
	Reserve() *rate.Reservation
	GetStats() *RateLimiterStats
	UpdateLimits(requests int, window time.Duration) error
}

// RateLimiterStats contains statistics about rate limiting
type RateLimiterStats struct {
	RequestsAllowed   int64     `json:"requests_allowed"`
	RequestsBlocked   int64     `json:"requests_blocked"`
	CurrentRate       float64   `json:"current_rate"`
	BurstCapacity     int       `json:"burst_capacity"`
	TokensAvailable   int       `json:"tokens_available"`
	LastRequest       time.Time `json:"last_request"`
	LastReset         time.Time `json:"last_reset"`
	WindowDuration    time.Duration `json:"window_duration"`
}

// TokenBucketLimiter implements rate limiting using token bucket algorithm
type TokenBucketLimiter struct {
	limiter         *rate.Limiter
	requestsAllowed int64
	requestsBlocked int64
	lastRequest     time.Time
	lastReset       time.Time
	windowDuration  time.Duration
	mu              sync.RWMutex
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(requestsPerSecond float64, burstSize int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		limiter:        rate.NewLimiter(rate.Limit(requestsPerSecond), burstSize),
		lastReset:      time.Now(),
		windowDuration: time.Second,
	}
}

// Wait waits until the rate limiter allows the request
func (tbl *TokenBucketLimiter) Wait(ctx context.Context) error {
	err := tbl.limiter.Wait(ctx)
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	
	if err == nil {
		tbl.requestsAllowed++
		tbl.lastRequest = time.Now()
	} else {
		tbl.requestsBlocked++
	}
	
	return err
}

// Allow checks if a request is allowed without blocking
func (tbl *TokenBucketLimiter) Allow() bool {
	allowed := tbl.limiter.Allow()
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	
	if allowed {
		tbl.requestsAllowed++
		tbl.lastRequest = time.Now()
	} else {
		tbl.requestsBlocked++
	}
	
	return allowed
}

// Reserve reserves a token for future use
func (tbl *TokenBucketLimiter) Reserve() *rate.Reservation {
	reservation := tbl.limiter.Reserve()
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	
	if reservation.OK() {
		tbl.requestsAllowed++
		tbl.lastRequest = time.Now()
	} else {
		tbl.requestsBlocked++
	}
	
	return reservation
}

// GetStats returns current rate limiter statistics
func (tbl *TokenBucketLimiter) GetStats() *RateLimiterStats {
	tbl.mu.RLock()
	defer tbl.mu.RUnlock()
	
	return &RateLimiterStats{
		RequestsAllowed: tbl.requestsAllowed,
		RequestsBlocked: tbl.requestsBlocked,
		CurrentRate:     float64(tbl.limiter.Limit()),
		BurstCapacity:   tbl.limiter.Burst(),
		TokensAvailable: int(tbl.limiter.Tokens()),
		LastRequest:     tbl.lastRequest,
		LastReset:       tbl.lastReset,
		WindowDuration:  tbl.windowDuration,
	}
}

// UpdateLimits updates the rate limiting parameters
func (tbl *TokenBucketLimiter) UpdateLimits(requests int, window time.Duration) error {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	
	requestsPerSecond := float64(requests) / window.Seconds()
	tbl.limiter.SetLimit(rate.Limit(requestsPerSecond))
	tbl.limiter.SetBurst(requests)
	tbl.windowDuration = window
	tbl.lastReset = time.Now()
	
	log.Printf("Rate limiter updated: %.2f req/s, burst: %d", requestsPerSecond, requests)
	return nil
}

// PlatformRateLimiter manages rate limiters for different platforms
type PlatformRateLimiter struct {
	limiters map[string]RateLimiter
	configs  map[string]*PlatformLimitConfig
	mu       sync.RWMutex
}

// PlatformLimitConfig contains rate limiting configuration for a platform
type PlatformLimitConfig struct {
	Platform           string        `json:"platform"`
	RequestsPerHour    int           `json:"requests_per_hour"`
	RequestsPerMinute  int           `json:"requests_per_minute"`
	BurstSize          int           `json:"burst_size"`
	BackoffMultiplier  float64       `json:"backoff_multiplier"`
	MaxBackoffDuration time.Duration `json:"max_backoff_duration"`
	RetryAttempts      int           `json:"retry_attempts"`
	Enabled            bool          `json:"enabled"`
}

// DefaultPlatformConfigs returns default rate limiting configurations
func DefaultPlatformConfigs() map[string]*PlatformLimitConfig {
	return map[string]*PlatformLimitConfig{
		"github": {
			Platform:           "github",
			RequestsPerHour:    5000,  // GitHub API limit
			RequestsPerMinute:  100,   // Conservative per-minute limit
			BurstSize:          10,    // Allow small bursts
			BackoffMultiplier:  2.0,   // Exponential backoff
			MaxBackoffDuration: 5 * time.Minute,
			RetryAttempts:      3,
			Enabled:            true,
		},
		"gitlab": {
			Platform:           "gitlab",
			RequestsPerHour:    2000,  // GitLab.com API limit
			RequestsPerMinute:  50,    // Conservative per-minute limit
			BurstSize:          5,     // Smaller burst for GitLab
			BackoffMultiplier:  2.0,
			MaxBackoffDuration: 5 * time.Minute,
			RetryAttempts:      3,
			Enabled:            true,
		},
		"bitbucket": {
			Platform:           "bitbucket",
			RequestsPerHour:    1000,  // Bitbucket API limit
			RequestsPerMinute:  30,    // Conservative per-minute limit
			BurstSize:          5,
			BackoffMultiplier:  2.0,
			MaxBackoffDuration: 5 * time.Minute,
			RetryAttempts:      3,
			Enabled:            true,
		},
		"azuredevops": {
			Platform:           "azuredevops",
			RequestsPerHour:    3600,  // Azure DevOps API limit
			RequestsPerMinute:  60,    // Conservative per-minute limit
			BurstSize:          10,
			BackoffMultiplier:  2.0,
			MaxBackoffDuration: 5 * time.Minute,
			RetryAttempts:      3,
			Enabled:            true,
		},
	}
}

// NewPlatformRateLimiter creates a new platform rate limiter
func NewPlatformRateLimiter(configs map[string]*PlatformLimitConfig) *PlatformRateLimiter {
	if configs == nil {
		configs = DefaultPlatformConfigs()
	}
	
	prl := &PlatformRateLimiter{
		limiters: make(map[string]RateLimiter),
		configs:  configs,
	}
	
	// Initialize rate limiters for each platform
	for platform, config := range configs {
		if config.Enabled {
			requestsPerSecond := float64(config.RequestsPerMinute) / 60.0
			prl.limiters[platform] = NewTokenBucketLimiter(requestsPerSecond, config.BurstSize)
			log.Printf("Initialized rate limiter for %s: %.2f req/s, burst: %d", 
				platform, requestsPerSecond, config.BurstSize)
		}
	}
	
	return prl
}

// GetLimiter returns the rate limiter for a specific platform
func (prl *PlatformRateLimiter) GetLimiter(platform string) (RateLimiter, error) {
	prl.mu.RLock()
	defer prl.mu.RUnlock()
	
	limiter, exists := prl.limiters[platform]
	if !exists {
		return nil, fmt.Errorf("no rate limiter configured for platform: %s", platform)
	}
	
	return limiter, nil
}

// Wait waits for rate limit approval for a specific platform
func (prl *PlatformRateLimiter) Wait(ctx context.Context, platform string) error {
	limiter, err := prl.GetLimiter(platform)
	if err != nil {
		return err
	}
	
	return limiter.Wait(ctx)
}

// Allow checks if a request is allowed for a specific platform
func (prl *PlatformRateLimiter) Allow(platform string) (bool, error) {
	limiter, err := prl.GetLimiter(platform)
	if err != nil {
		return false, err
	}
	
	return limiter.Allow(), nil
}

// GetStats returns statistics for all platform rate limiters
func (prl *PlatformRateLimiter) GetStats() map[string]*RateLimiterStats {
	prl.mu.RLock()
	defer prl.mu.RUnlock()
	
	stats := make(map[string]*RateLimiterStats)
	for platform, limiter := range prl.limiters {
		stats[platform] = limiter.GetStats()
	}
	
	return stats
}

// UpdatePlatformLimits updates rate limits for a specific platform
func (prl *PlatformRateLimiter) UpdatePlatformLimits(platform string, config *PlatformLimitConfig) error {
	prl.mu.Lock()
	defer prl.mu.Unlock()
	
	prl.configs[platform] = config
	
	if config.Enabled {
		requestsPerSecond := float64(config.RequestsPerMinute) / 60.0
		
		if limiter, exists := prl.limiters[platform]; exists {
			// Update existing limiter
			return limiter.UpdateLimits(config.RequestsPerMinute, time.Minute)
		} else {
			// Create new limiter
			prl.limiters[platform] = NewTokenBucketLimiter(requestsPerSecond, config.BurstSize)
		}
	} else {
		// Remove limiter if disabled
		delete(prl.limiters, platform)
	}
	
	log.Printf("Updated rate limiter for %s: enabled=%v", platform, config.Enabled)
	return nil
}

// AdaptiveRateLimiter adjusts rate limits based on API responses
type AdaptiveRateLimiter struct {
	baseLimiter     RateLimiter
	platform        string
	currentBackoff  time.Duration
	maxBackoff      time.Duration
	backoffMultiplier float64
	retryAttempts   int
	consecutiveErrors int
	lastError       time.Time
	mu              sync.RWMutex
}

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(baseLimiter RateLimiter, platform string, config *PlatformLimitConfig) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		baseLimiter:       baseLimiter,
		platform:          platform,
		maxBackoff:        config.MaxBackoffDuration,
		backoffMultiplier: config.BackoffMultiplier,
		retryAttempts:     config.RetryAttempts,
	}
}

// Wait waits with adaptive backoff
func (arl *AdaptiveRateLimiter) Wait(ctx context.Context) error {
	arl.mu.RLock()
	backoff := arl.currentBackoff
	arl.mu.RUnlock()
	
	// Apply additional backoff if needed
	if backoff > 0 {
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	
	return arl.baseLimiter.Wait(ctx)
}

// Allow checks if request is allowed
func (arl *AdaptiveRateLimiter) Allow() bool {
	arl.mu.RLock()
	backoff := arl.currentBackoff
	arl.mu.RUnlock()
	
	// Don't allow if in backoff period
	if backoff > 0 && time.Since(arl.lastError) < backoff {
		return false
	}
	
	return arl.baseLimiter.Allow()
}

// Reserve reserves a token
func (arl *AdaptiveRateLimiter) Reserve() *rate.Reservation {
	return arl.baseLimiter.Reserve()
}

// GetStats returns rate limiter statistics
func (arl *AdaptiveRateLimiter) GetStats() *RateLimiterStats {
	stats := arl.baseLimiter.GetStats()
	
	arl.mu.RLock()
	stats.RequestsBlocked += int64(arl.consecutiveErrors)
	arl.mu.RUnlock()
	
	return stats
}

// UpdateLimits updates the underlying rate limiter
func (arl *AdaptiveRateLimiter) UpdateLimits(requests int, window time.Duration) error {
	return arl.baseLimiter.UpdateLimits(requests, window)
}

// OnSuccess resets backoff on successful request
func (arl *AdaptiveRateLimiter) OnSuccess() {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	arl.consecutiveErrors = 0
	arl.currentBackoff = 0
}

// OnError increases backoff on error
func (arl *AdaptiveRateLimiter) OnError(err error) {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	arl.consecutiveErrors++
	arl.lastError = time.Now()
	
	// Increase backoff exponentially
	if arl.currentBackoff == 0 {
		arl.currentBackoff = time.Second
	} else {
		arl.currentBackoff = time.Duration(float64(arl.currentBackoff) * arl.backoffMultiplier)
	}
	
	// Cap at maximum backoff
	if arl.currentBackoff > arl.maxBackoff {
		arl.currentBackoff = arl.maxBackoff
	}
	
	log.Printf("Rate limiter backoff for %s: %v (consecutive errors: %d)", 
		arl.platform, arl.currentBackoff, arl.consecutiveErrors)
}

// ShouldRetry determines if a request should be retried
func (arl *AdaptiveRateLimiter) ShouldRetry() bool {
	arl.mu.RLock()
	defer arl.mu.RUnlock()
	
	return arl.consecutiveErrors < arl.retryAttempts
}

// RateLimitedExecutor executes functions with rate limiting and retry logic
type RateLimitedExecutor struct {
	platformLimiter *PlatformRateLimiter
	adaptiveLimiters map[string]*AdaptiveRateLimiter
	mu              sync.RWMutex
}

// NewRateLimitedExecutor creates a new rate limited executor
func NewRateLimitedExecutor(platformLimiter *PlatformRateLimiter) *RateLimitedExecutor {
	return &RateLimitedExecutor{
		platformLimiter:  platformLimiter,
		adaptiveLimiters: make(map[string]*AdaptiveRateLimiter),
	}
}

// Execute executes a function with rate limiting and retry logic
func (rle *RateLimitedExecutor) Execute(ctx context.Context, platform string, fn func() error) error {
	adaptiveLimiter := rle.getOrCreateAdaptiveLimiter(platform)
	
	var lastErr error
	for attempt := 0; attempt < adaptiveLimiter.retryAttempts; attempt++ {
		// Wait for rate limit approval
		if err := adaptiveLimiter.Wait(ctx); err != nil {
			return fmt.Errorf("rate limit wait failed: %w", err)
		}
		
		// Execute the function
		err := fn()
		if err == nil {
			adaptiveLimiter.OnSuccess()
			return nil
		}
		
		lastErr = err
		
		// Check if this is a rate limit error
		if isRateLimitError(err) {
			adaptiveLimiter.OnError(err)
			
			if !adaptiveLimiter.ShouldRetry() {
				break
			}
			
			log.Printf("Rate limit hit for %s, retrying (attempt %d/%d)", 
				platform, attempt+1, adaptiveLimiter.retryAttempts)
			continue
		}
		
		// For non-rate-limit errors, don't retry
		break
	}
	
	return lastErr
}

// getOrCreateAdaptiveLimiter gets or creates an adaptive limiter for a platform
func (rle *RateLimitedExecutor) getOrCreateAdaptiveLimiter(platform string) *AdaptiveRateLimiter {
	rle.mu.RLock()
	adaptiveLimiter, exists := rle.adaptiveLimiters[platform]
	rle.mu.RUnlock()
	
	if exists {
		return adaptiveLimiter
	}
	
	rle.mu.Lock()
	defer rle.mu.Unlock()
	
	// Double-check after acquiring write lock
	if adaptiveLimiter, exists := rle.adaptiveLimiters[platform]; exists {
		return adaptiveLimiter
	}
	
	// Get base limiter and config
	baseLimiter, err := rle.platformLimiter.GetLimiter(platform)
	if err != nil {
		// Fallback to default limiter
		baseLimiter = NewTokenBucketLimiter(1.0, 1) // 1 req/s, burst 1
	}
	
	config := rle.platformLimiter.configs[platform]
	if config == nil {
		config = &PlatformLimitConfig{
			BackoffMultiplier:  2.0,
			MaxBackoffDuration: 5 * time.Minute,
			RetryAttempts:      3,
		}
	}
	
	adaptiveLimiter = NewAdaptiveRateLimiter(baseLimiter, platform, config)
	rle.adaptiveLimiters[platform] = adaptiveLimiter
	
	return adaptiveLimiter
}

// isRateLimitError checks if an error is a rate limit error
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	
	errorStr := err.Error()
	
	// Common rate limit error patterns
	rateLimitPatterns := []string{
		"rate limit",
		"too many requests",
		"429",
		"quota exceeded",
		"api rate limit exceeded",
		"rate_limit_exceeded",
		"abuse detection",
	}
	
	for _, pattern := range rateLimitPatterns {
		if contains(errorStr, pattern) {
			return true
		}
	}
	
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		(s == substr || 
		 len(s) > len(substr) && 
		 (s[:len(substr)] == substr || 
		  s[len(s)-len(substr):] == substr || 
		  indexOfSubstring(s, substr) >= 0))
}

// indexOfSubstring finds the index of a substring (case-insensitive)
func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// GetAllStats returns statistics for all rate limiters
func (rle *RateLimitedExecutor) GetAllStats() map[string]*RateLimiterStats {
	stats := rle.platformLimiter.GetStats()
	
	rle.mu.RLock()
	for platform, adaptiveLimiter := range rle.adaptiveLimiters {
		if _, exists := stats[platform]; !exists {
			stats[platform] = adaptiveLimiter.GetStats()
		}
	}
	rle.mu.RUnlock()
	
	return stats
}