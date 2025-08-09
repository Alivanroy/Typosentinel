package integration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Alivanroy/Typosentinel/internal/orchestrator"
)

// TestRateLimitingUnderLoad tests rate limiting functionality under concurrent load
func TestRateLimitingUnderLoad(t *testing.T) {
	tests := []struct {
		name              string
		requestsPerSecond float64
		burstSize         int
		concurrentClients int
		requestsPerClient int
		expectedBlocked   bool
	}{
		{
			name:              "Low Load",
			requestsPerSecond: 10.0,
			burstSize:         5,
			concurrentClients: 5,
			requestsPerClient: 10,
			expectedBlocked:   true,
		},
		{
			name:              "Medium Load",
			requestsPerSecond: 50.0,
			burstSize:         10,
			concurrentClients: 20,
			requestsPerClient: 15,
			expectedBlocked:   true,
		},
		{
			name:              "High Load",
			requestsPerSecond: 100.0,
			burstSize:         20,
			concurrentClients: 50,
			requestsPerClient: 20,
			expectedBlocked:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create rate limiter
			limiter := orchestrator.NewTokenBucketLimiter(
				tt.requestsPerSecond,
				tt.burstSize,
			)

			var allowedRequests int64
			var blockedRequests int64
			var wg sync.WaitGroup

			start := time.Now()

			// Launch concurrent clients
			for i := 0; i < tt.concurrentClients; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					for j := 0; j < tt.requestsPerClient; j++ {
						if limiter.Allow() {
							atomic.AddInt64(&allowedRequests, 1)
						} else {
							atomic.AddInt64(&blockedRequests, 1)
						}
						time.Sleep(10 * time.Millisecond)
					}
				}()
			}

			wg.Wait()
			duration := time.Since(start)

			totalRequests := int64(tt.concurrentClients * tt.requestsPerClient)

			t.Logf("%s completed in %v", tt.name, duration)
			t.Logf("Total requests: %d", totalRequests)
			t.Logf("Allowed requests: %d", allowedRequests)
			t.Logf("Blocked requests: %d", blockedRequests)

			// Verify basic functionality
			assert.Equal(t, totalRequests, allowedRequests+blockedRequests)
			assert.Greater(t, allowedRequests, int64(0), "Expected some requests to be allowed")

			if tt.expectedBlocked {
				assert.Greater(t, blockedRequests, int64(0), "Expected some requests to be blocked under load")
			}

			// Verify stats
			stats := limiter.GetStats()
			assert.NotNil(t, stats)
			assert.Equal(t, allowedRequests, stats.RequestsAllowed)
			assert.Equal(t, blockedRequests, stats.RequestsBlocked)
		})
	}
}

// TestPlatformRateLimitingIntegration tests platform-specific rate limiting
func TestPlatformRateLimitingIntegration(t *testing.T) {
	// Create platform rate limiter with default configs
	platformLimiter := orchestrator.NewPlatformRateLimiter(nil)

	t.Run("GitHub Rate Limiting", func(t *testing.T) {
		var allowedCount int64
		var blockedCount int64

		// Test burst behavior
		for i := 0; i < 15; i++ { // More than burst size
			allowed, err := platformLimiter.Allow("github")
			require.NoError(t, err)
			if allowed {
				atomic.AddInt64(&allowedCount, 1)
			} else {
				atomic.AddInt64(&blockedCount, 1)
			}
			time.Sleep(50 * time.Millisecond)
		}

		t.Logf("GitHub - Allowed: %d, Blocked: %d", allowedCount, blockedCount)
		assert.Greater(t, allowedCount, int64(0), "Expected some GitHub requests to be allowed")
	})

	t.Run("Platform Independence", func(t *testing.T) {
		// Test that different platforms have independent rate limits
		var allowedCount int64

		// Use up GitHub rate limit
		for i := 0; i < 20; i++ {
			allowed, err := platformLimiter.Allow("github")
			require.NoError(t, err)
			if allowed {
				atomic.AddInt64(&allowedCount, 1)
			}
			time.Sleep(10 * time.Millisecond)
		}

		// GitLab should still work independently
		gitlabAllowed, err := platformLimiter.Allow("gitlab")
		require.NoError(t, err)
		assert.True(t, gitlabAllowed, "GitLab rate limiting should be independent of GitHub")
	})

	t.Run("Platform Stats", func(t *testing.T) {
		stats := platformLimiter.GetStats()
		assert.NotNil(t, stats)

		for platform, stat := range stats {
			t.Logf("Platform %s stats: %+v", platform, stat)
			assert.NotNil(t, stat)
		}
	})

	t.Run("Unknown Platform Error", func(t *testing.T) {
		allowed, err := platformLimiter.Allow("unknown-platform")
		assert.Error(t, err)
		assert.False(t, allowed)
	})
}

// TestAdaptiveRateLimitingBehavior tests adaptive rate limiting under error conditions
func TestAdaptiveRateLimitingBehavior(t *testing.T) {
	baseLimiter := orchestrator.NewTokenBucketLimiter(10.0, 5)

	config := &orchestrator.PlatformLimitConfig{
		Platform:           "test",
		RequestsPerHour:    600,
		RequestsPerMinute:  10,
		BurstSize:          5,
		BackoffMultiplier:  2.0,
		MaxBackoffDuration: 10 * time.Second,
		RetryAttempts:      3,
		Enabled:            true,
	}

	adaptiveLimiter := orchestrator.NewAdaptiveRateLimiter(baseLimiter, "test", config)

	ctx := context.Background()

	t.Run("Normal Operation", func(t *testing.T) {
		// Test normal operation
		for i := 0; i < 5; i++ {
			allowed := adaptiveLimiter.Allow()
			if allowed {
				adaptiveLimiter.OnSuccess()
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Should work normally
		err := adaptiveLimiter.Wait(ctx)
		assert.NoError(t, err)
	})

	t.Run("Error Backoff", func(t *testing.T) {
		// Simulate consecutive errors
		for i := 0; i < 5; i++ {
			adaptiveLimiter.OnError(fmt.Errorf("simulated error %d", i))
		}

		// Test that requests are now being throttled more aggressively
		start := time.Now()
		allowed := adaptiveLimiter.Allow()
		duration := time.Since(start)

		t.Logf("Allow call took: %v, allowed: %v", duration, allowed)

		// After errors, should have some form of throttling
		stats := adaptiveLimiter.GetStats()
		assert.NotNil(t, stats)
		t.Logf("Adaptive limiter stats after errors: %+v", stats)
	})

	t.Run("Recovery After Success", func(t *testing.T) {
		// Test recovery after success
		adaptiveLimiter.OnSuccess()

		start := time.Now()
		err := adaptiveLimiter.Wait(ctx)
		duration := time.Since(start)

		assert.NoError(t, err)
		t.Logf("Wait after success took: %v", duration)

		// Get final stats
		stats := adaptiveLimiter.GetStats()
		assert.NotNil(t, stats)
		t.Logf("Final adaptive limiter stats: %+v", stats)
	})
}

// BenchmarkRateLimiterPerformance benchmarks rate limiter performance
func BenchmarkRateLimiterPerformance(b *testing.B) {
	limiter := orchestrator.NewTokenBucketLimiter(1000.0, 100)

	b.Run("Sequential", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			limiter.Allow()
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				limiter.Allow()
			}
		})
	})

	b.Run("WithStats", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			limiter.Allow()
			if i%100 == 0 {
				limiter.GetStats()
			}
		}
	})
}