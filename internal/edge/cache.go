package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// CacheBackend represents a pluggable cache backend
type CacheBackend interface {
	Get(ctx context.Context, key string) ([]string, bool, error)
	Set(ctx context.Context, key string, value []string, ttl time.Duration) error
	Clear(ctx context.Context) error
	Close() error
}

// InMemoryCache provides a simple in-memory cache implementation
type InMemoryCache struct {
	data       map[string]cacheEntry
	mu         *sync.RWMutex
	defaultTTL time.Duration
}

type cacheEntry struct {
	value     []string
	expiresAt time.Time
}

// NewInMemoryCache creates a new in-memory cache
func NewInMemoryCache(ttl time.Duration) *InMemoryCache {
	return &InMemoryCache{
		data:       make(map[string]cacheEntry),
		mu:         &sync.RWMutex{},
		defaultTTL: ttl,
	}
}

func (c *InMemoryCache) Get(ctx context.Context, key string) ([]string, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false, nil
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil, false, nil
	}

	return entry.value, true, nil
}

func (c *InMemoryCache) Set(ctx context.Context, key string, value []string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	c.data[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (c *InMemoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]cacheEntry)
	return nil
}

func (c *InMemoryCache) Close() error {
	return nil
}

// RedisCache provides a Redis-backed cache implementation
type RedisCache struct {
	client     *redis.Client
	prefix     string
	defaultTTL time.Duration
}

// RedisCacheConfig holds Redis connection configuration
type RedisCacheConfig struct {
	Address    string        // Redis server address (e.g., "localhost:6379")
	Password   string        // Redis password (empty for no auth)
	DB         int           // Redis database number
	Prefix     string        // Key prefix for namespacing
	DefaultTTL time.Duration // Default TTL for cache entries
}

// NewRedisCache creates a new Redis cache backend
func NewRedisCache(config *RedisCacheConfig) (*RedisCache, error) {
	if config == nil {
		return nil, fmt.Errorf("Redis cache config cannot be nil")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     config.Address,
		Password: config.Password,
		DB:       config.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis connection failed: %w", err)
	}

	ttl := config.DefaultTTL
	if ttl == 0 {
		ttl = 10 * time.Minute // Default to 10 minutes
	}

	prefix := config.Prefix
	if prefix == "" {
		prefix = "typosentinel:gtr:"
	}

	return &RedisCache{
		client:     client,
		prefix:     prefix,
		defaultTTL: ttl,
	}, nil
}

func (c *RedisCache) Get(ctx context.Context, key string) ([]string, bool, error) {
	fullKey := c.prefix + key

	data, err := c.client.Get(ctx, fullKey).Result()
	if err == redis.Nil {
		return nil, false, nil // Key doesn't exist
	}
	if err != nil {
		return nil, false, fmt.Errorf("Redis GET failed: %w", err)
	}

	var value []string
	if err := json.Unmarshal([]byte(data), &value); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal cached value: %w", err)
	}

	return value, true, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, value []string, ttl time.Duration) error {
	fullKey := c.prefix + key

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	if err := c.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		return fmt.Errorf("Redis SET failed: %w", err)
	}

	return nil
}

func (c *RedisCache) Clear(ctx context.Context) error {
	// Delete all keys with our prefix
	pattern := c.prefix + "*"
	iter := c.client.Scan(ctx, 0, pattern, 0).Iterator()

	for iter.Next(ctx) {
		if err := c.client.Del(ctx, iter.Val()).Err(); err != nil {
			return fmt.Errorf("Redis DELETE failed: %w", err)
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("Redis SCAN failed: %w", err)
	}

	return nil
}

func (c *RedisCache) Close() error {
	return c.client.Close()
}
