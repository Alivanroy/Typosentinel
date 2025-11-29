package middleware

import (
	"context"
	"fmt"
	"time"

	apimetrics "github.com/Alivanroy/Typosentinel/internal/api/metrics"
	redis "github.com/redis/go-redis/v9"
)

type RedisLimiter struct {
	client *redis.Client
	policy RatePolicy
}

func NewRedisLimiter(dsn string, policy RatePolicy) (*RedisLimiter, error) {
	opt, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, err
	}
	c := redis.NewClient(opt)
	ctx := context.Background()
	pingErr := c.Ping(ctx).Err()
	apimetrics.SetRedisConnected(pingErr == nil)
	return &RedisLimiter{client: c, policy: policy}, nil
}

func (l *RedisLimiter) Allow(key string) bool {
	ctx := context.Background()
	windowSecs := int64(l.policy.Window / time.Second)
	bucket := time.Now().Unix() / windowSecs
	k := fmt.Sprintf("rate:%s:%d", key, bucket)
	count, err := l.client.Incr(ctx, k).Result()
	if err != nil {
		apimetrics.SetRedisConnected(false)
		return true
	}
	apimetrics.SetRedisConnected(true)
	if count == 1 {
		_ = l.client.Expire(ctx, k, l.policy.Window).Err()
	}
	return int(count) <= l.policy.Limit
}
