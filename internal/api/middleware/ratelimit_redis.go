package middleware

import (
    "context"
    "fmt"
    "time"

    redis "github.com/redis/go-redis/v9"
)

type RedisLimiter struct{
    client *redis.Client
    policy RatePolicy
}

func NewRedisLimiter(dsn string, policy RatePolicy) (*RedisLimiter, error){
    opt, err := redis.ParseURL(dsn)
    if err != nil { return nil, err }
    c := redis.NewClient(opt)
    return &RedisLimiter{client: c, policy: policy}, nil
}

func (l *RedisLimiter) Allow(key string) bool{
    ctx := context.Background()
    windowSecs := int64(l.policy.Window / time.Second)
    bucket := time.Now().Unix() / windowSecs
    k := fmt.Sprintf("rate:%s:%d", key, bucket)
    count, err := l.client.Incr(ctx, k).Result()
    if err != nil { return true }
    if count == 1 { _ = l.client.Expire(ctx, k, l.policy.Window).Err() }
    return int(count) <= l.policy.Limit
}

