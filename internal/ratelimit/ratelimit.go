package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

// RateLimiter interface defines the rate limiting operations
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
	Reset(ctx context.Context, key string) error
	GetUsage(ctx context.Context, key string) (int, error)
}

// RedisRateLimiter implements rate limiting using Redis
type RedisRateLimiter struct {
	client *redis.Client
}

// MemoryRateLimiter implements rate limiting using in-memory storage
type MemoryRateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*bucket
}

type bucket struct {
	count     int
	resetTime time.Time
	window    time.Duration
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(redisURL string) (*RedisRateLimiter, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisRateLimiter{client: client}, nil
}

// NewMemoryRateLimiter creates a new in-memory rate limiter
func NewMemoryRateLimiter() *MemoryRateLimiter {
	limiter := &MemoryRateLimiter{
		buckets: make(map[string]*bucket),
	}

	// Start cleanup goroutine
	go limiter.cleanup()

	return limiter
}

// Allow checks if a request is allowed under the rate limit
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	script := `
		local key = KEYS[1]
		local limit = tonumber(ARGV[1])
		local window = tonumber(ARGV[2])
		local current_time = tonumber(ARGV[3])
		
		local current = redis.call('GET', key)
		if current == false then
			redis.call('SET', key, 1)
			redis.call('EXPIRE', key, window)
			return 1
		end
		
		current = tonumber(current)
		if current < limit then
			redis.call('INCR', key)
			return 1
		else
			return 0
		end
	`

	result, err := r.client.Eval(ctx, script, []string{key}, limit, int(window.Seconds()), time.Now().Unix()).Result()
	if err != nil {
		return false, fmt.Errorf("Redis rate limit check failed: %w", err)
	}

	allowed, ok := result.(int64)
	if !ok {
		return false, fmt.Errorf("unexpected Redis response type")
	}

	return allowed == 1, nil
}

// Reset resets the rate limit for a key
func (r *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// GetUsage returns the current usage count for a key
func (r *RedisRateLimiter) GetUsage(ctx context.Context, key string) (int, error) {
	result, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	count, err := strconv.Atoi(result)
	if err != nil {
		return 0, fmt.Errorf("invalid count value in Redis: %w", err)
	}

	return count, nil
}

// Allow checks if a request is allowed under the rate limit (memory implementation)
func (m *MemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	b, exists := m.buckets[key]

	if !exists || now.After(b.resetTime) {
		// Create new bucket or reset expired bucket
		m.buckets[key] = &bucket{
			count:     1,
			resetTime: now.Add(window),
			window:    window,
		}
		return true, nil
	}

	if b.count >= limit {
		return false, nil
	}

	b.count++
	return true, nil
}

// Reset resets the rate limit for a key (memory implementation)
func (m *MemoryRateLimiter) Reset(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.buckets, key)
	return nil
}

// GetUsage returns the current usage count for a key (memory implementation)
func (m *MemoryRateLimiter) GetUsage(ctx context.Context, key string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	b, exists := m.buckets[key]
	if !exists {
		return 0, nil
	}

	if time.Now().After(b.resetTime) {
		return 0, nil
	}

	return b.count, nil
}

// cleanup removes expired buckets from memory
func (m *MemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for key, bucket := range m.buckets {
			if now.After(bucket.resetTime) {
				delete(m.buckets, key)
			}
		}
		m.mu.Unlock()
	}
}

// FallbackRateLimiter combines Redis and memory rate limiters with fallback
type FallbackRateLimiter struct {
	primary     RateLimiter
	fallback    RateLimiter
	useFallback bool
}

// NewFallbackRateLimiter creates a rate limiter with Redis primary and memory fallback
func NewFallbackRateLimiter(redisURL string) *FallbackRateLimiter {
	var primary RateLimiter
	useFallback := false

	if redisURL != "" {
		redis, err := NewRedisRateLimiter(redisURL)
		if err == nil {
			primary = redis
		} else {
			useFallback = true
		}
	} else {
		useFallback = true
	}

	fallback := NewMemoryRateLimiter()

	if useFallback {
		primary = fallback
	}

	return &FallbackRateLimiter{
		primary:     primary,
		fallback:    fallback,
		useFallback: useFallback,
	}
}

// Allow checks if a request is allowed, with fallback to memory if Redis fails
func (f *FallbackRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	allowed, err := f.primary.Allow(ctx, key, limit, window)
	if err != nil && !f.useFallback {
		// Fallback to memory limiter if Redis fails
		return f.fallback.Allow(ctx, key, limit, window)
	}
	return allowed, err
}

// Reset resets the rate limit for a key
func (f *FallbackRateLimiter) Reset(ctx context.Context, key string) error {
	err := f.primary.Reset(ctx, key)
	if err != nil && !f.useFallback {
		return f.fallback.Reset(ctx, key)
	}
	return err
}

// GetUsage returns the current usage count for a key
func (f *FallbackRateLimiter) GetUsage(ctx context.Context, key string) (int, error) {
	usage, err := f.primary.GetUsage(ctx, key)
	if err != nil && !f.useFallback {
		return f.fallback.GetUsage(ctx, key)
	}
	return usage, err
}
