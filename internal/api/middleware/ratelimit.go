package middleware

import (
	"net/http"
	"sync"
	"time"
)

type RatePolicy struct {
	Limit  int
	Window time.Duration
}

type LocalLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	policy RatePolicy
}

func NewLocalLimiter(policy RatePolicy) *LocalLimiter {
	return &LocalLimiter{hits: make(map[string][]time.Time), policy: policy}
}

func (l *LocalLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-l.policy.Window)
	var valid []time.Time
	for _, t := range l.hits[key] {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= l.policy.Limit {
		l.hits[key] = valid
		return false
	}
	l.hits[key] = append(valid, now)
	return true
}

func RateLimitMiddleware(l *LocalLimiter, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if !l.Allow(key) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, `{"error": "Rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
