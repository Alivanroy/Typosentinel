package loadbalancer

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// LoadBalancingStrategy defines the load balancing algorithm
type LoadBalancingStrategy string

const (
	RoundRobin    LoadBalancingStrategy = "round_robin"
	LeastConnections LoadBalancingStrategy = "least_connections"
	WeightedRoundRobin LoadBalancingStrategy = "weighted_round_robin"
	IPHash        LoadBalancingStrategy = "ip_hash"
	HealthBased   LoadBalancingStrategy = "health_based"
)

// Backend represents a backend server
type Backend struct {
	ID          string    `json:"id"`
	URL         *url.URL  `json:"url"`
	Weight      int       `json:"weight"`
	Healthy     bool      `json:"healthy"`
	Connections int64     `json:"connections"`
	LastCheck   time.Time `json:"last_check"`
	ResponseTime time.Duration `json:"response_time"`
	Failures    int       `json:"failures"`
	Proxy       *httputil.ReverseProxy `json:"-"`
	mu          sync.RWMutex `json:"-"`
}

// LoadBalancer manages traffic distribution across backend servers
type LoadBalancer struct {
	backends    []*Backend
	strategy    LoadBalancingStrategy
	current     uint64
	redis       *redis.Client
	metrics     *metrics.Metrics
	healthCheck *HealthChecker
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// HealthChecker performs health checks on backend servers
type HealthChecker struct {
	interval    time.Duration
	timeout     time.Duration
	healthPath  string
	expectedCode int
	mu          sync.RWMutex
}

// LoadBalancerConfig holds configuration for the load balancer
type LoadBalancerConfig struct {
	Strategy         LoadBalancingStrategy `json:"strategy"`
	HealthCheckInterval time.Duration      `json:"health_check_interval"`
	HealthCheckTimeout  time.Duration      `json:"health_check_timeout"`
	HealthCheckPath     string             `json:"health_check_path"`
	ExpectedStatusCode  int                `json:"expected_status_code"`
}

// NewLoadBalancer creates a new load balancer instance
func NewLoadBalancer(config LoadBalancerConfig, redis *redis.Client) *LoadBalancer {
	ctx, cancel := context.WithCancel(context.Background())

	healthChecker := &HealthChecker{
		interval:    config.HealthCheckInterval,
		timeout:     config.HealthCheckTimeout,
		healthPath:  config.HealthCheckPath,
		expectedCode: config.ExpectedStatusCode,
	}

	if healthChecker.interval == 0 {
		healthChecker.interval = 30 * time.Second
	}
	if healthChecker.timeout == 0 {
		healthChecker.timeout = 5 * time.Second
	}
	if healthChecker.healthPath == "" {
		healthChecker.healthPath = "/health"
	}
	if healthChecker.expectedCode == 0 {
		healthChecker.expectedCode = http.StatusOK
	}

	return &LoadBalancer{
		backends:    make([]*Backend, 0),
		strategy:    config.Strategy,
		redis:       redis,
		metrics:     metrics.GetInstance(),
		healthCheck: healthChecker,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// AddBackend adds a new backend server
func (lb *LoadBalancer) AddBackend(id string, targetURL string, weight int) error {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid backend URL %s: %w", targetURL, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)
	
	// Customize the proxy to add load balancer headers and metrics
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-By", "typosentinel-lb")
		req.Header.Set("X-Backend-ID", id)
	}

	// Add error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Backend %s error: %v", id, err)
		lb.metrics.LoadBalancerErrors.WithLabelValues(id, "proxy_error").Inc()
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Backend server unavailable"))
	}

	backend := &Backend{
		ID:      id,
		URL:     parsedURL,
		Weight:  weight,
		Healthy: true,
		Proxy:   proxy,
	}

	lb.mu.Lock()
	lb.backends = append(lb.backends, backend)
	lb.mu.Unlock()

	// Start health checking for this backend
	go lb.startHealthCheck(backend)

	log.Printf("Added backend %s (%s) with weight %d", id, targetURL, weight)
	return nil
}

// RemoveBackend removes a backend server
func (lb *LoadBalancer) RemoveBackend(id string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i, backend := range lb.backends {
		if backend.ID == id {
			lb.backends = append(lb.backends[:i], lb.backends[i+1:]...)
			log.Printf("Removed backend %s", id)
			return nil
		}
	}

	return fmt.Errorf("backend %s not found", id)
}

// GetNextBackend selects the next backend based on the load balancing strategy
func (lb *LoadBalancer) GetNextBackend(clientIP string) (*Backend, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	healthyBackends := lb.getHealthyBackends()
	if len(healthyBackends) == 0 {
		return nil, fmt.Errorf("no healthy backends available")
	}

	switch lb.strategy {
	case RoundRobin:
		return lb.roundRobin(healthyBackends), nil
	case LeastConnections:
		return lb.leastConnections(healthyBackends), nil
	case WeightedRoundRobin:
		return lb.weightedRoundRobin(healthyBackends), nil
	case IPHash:
		return lb.ipHash(healthyBackends, clientIP), nil
	case HealthBased:
		return lb.healthBased(healthyBackends), nil
	default:
		return lb.roundRobin(healthyBackends), nil
	}
}

// getHealthyBackends returns only healthy backends
func (lb *LoadBalancer) getHealthyBackends() []*Backend {
	healthy := make([]*Backend, 0)
	for _, backend := range lb.backends {
		backend.mu.RLock()
		if backend.Healthy {
			healthy = append(healthy, backend)
		}
		backend.mu.RUnlock()
	}
	return healthy
}

// roundRobin implements round-robin load balancing
func (lb *LoadBalancer) roundRobin(backends []*Backend) *Backend {
	next := atomic.AddUint64(&lb.current, 1)
	return backends[(next-1)%uint64(len(backends))]
}

// leastConnections implements least connections load balancing
func (lb *LoadBalancer) leastConnections(backends []*Backend) *Backend {
	var selected *Backend
	minConnections := int64(^uint64(0) >> 1) // Max int64

	for _, backend := range backends {
		backend.mu.RLock()
		connections := backend.Connections
		backend.mu.RUnlock()

		if connections < minConnections {
			minConnections = connections
			selected = backend
		}
	}

	return selected
}

// weightedRoundRobin implements weighted round-robin load balancing
func (lb *LoadBalancer) weightedRoundRobin(backends []*Backend) *Backend {
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}

	if totalWeight == 0 {
		return lb.roundRobin(backends)
	}

	next := atomic.AddUint64(&lb.current, 1)
	weightedIndex := (next - 1) % uint64(totalWeight)

	currentWeight := uint64(0)
	for _, backend := range backends {
		currentWeight += uint64(backend.Weight)
		if weightedIndex < currentWeight {
			return backend
		}
	}

	return backends[0] // Fallback
}

// ipHash implements IP hash-based load balancing for session affinity
func (lb *LoadBalancer) ipHash(backends []*Backend, clientIP string) *Backend {
	hash := lb.hashString(clientIP)
	return backends[hash%uint64(len(backends))]
}

// healthBased selects backend based on health metrics (response time, failures)
func (lb *LoadBalancer) healthBased(backends []*Backend) *Backend {
	var selected *Backend
	bestScore := float64(-1)

	for _, backend := range backends {
		backend.mu.RLock()
		// Calculate health score based on response time and failure rate
		responseTimeMs := float64(backend.ResponseTime.Milliseconds())
		failureRate := float64(backend.Failures) / 100.0 // Normalize failures
		
		// Lower is better for both metrics
		score := 1.0 / (1.0 + responseTimeMs/1000.0 + failureRate)
		backend.mu.RUnlock()

		if score > bestScore {
			bestScore = score
			selected = backend
		}
	}

	return selected
}

// hashString creates a hash from a string for consistent routing
func (lb *LoadBalancer) hashString(s string) uint64 {
	hash := uint64(5381)
	for _, c := range s {
		hash = ((hash << 5) + hash) + uint64(c)
	}
	return hash
}

// ServeHTTP implements the http.Handler interface
func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := lb.getClientIP(r)
	backend, err := lb.GetNextBackend(clientIP)
	if err != nil {
		log.Printf("No backend available: %v", err)
		lb.metrics.LoadBalancerErrors.WithLabelValues("none", "no_backend").Inc()
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Service temporarily unavailable"))
		return
	}

	// Increment connection count
	backend.mu.Lock()
	backend.Connections++
	backend.mu.Unlock()

	// Decrement connection count when done
	defer func() {
		backend.mu.Lock()
		backend.Connections--
		backend.mu.Unlock()
	}()

	// Record metrics
	start := time.Now()
	lb.metrics.LoadBalancerRequests.WithLabelValues(backend.ID).Inc()

	// Serve the request
	backend.Proxy.ServeHTTP(w, r)

	// Record response time
	duration := time.Since(start)
	lb.metrics.LoadBalancerResponseTime.WithLabelValues(backend.ID).Observe(duration.Seconds())

	// Update backend response time
	backend.mu.Lock()
	backend.ResponseTime = duration
	backend.mu.Unlock()
}

// getClientIP extracts the client IP from the request
func (lb *LoadBalancer) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := len(xff); idx > 0 {
			return xff[:idx]
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// startHealthCheck starts health checking for a backend
func (lb *LoadBalancer) startHealthCheck(backend *Backend) {
	ticker := time.NewTicker(lb.healthCheck.interval)
	defer ticker.Stop()

	for {
		select {
		case <-lb.ctx.Done():
			return
		case <-ticker.C:
			lb.performHealthCheck(backend)
		}
	}
}

// performHealthCheck performs a health check on a backend
func (lb *LoadBalancer) performHealthCheck(backend *Backend) {
	ctx, cancel := context.WithTimeout(lb.ctx, lb.healthCheck.timeout)
	defer cancel()

	healthURL := fmt.Sprintf("%s%s", backend.URL.String(), lb.healthCheck.healthPath)
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		lb.markBackendUnhealthy(backend, fmt.Sprintf("Failed to create health check request: %v", err))
		return
	}

	client := &http.Client{
		Timeout: lb.healthCheck.timeout,
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	backend.mu.Lock()
	backend.LastCheck = time.Now()
	backend.ResponseTime = duration
	backend.mu.Unlock()

	if err != nil {
		lb.markBackendUnhealthy(backend, fmt.Sprintf("Health check failed: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != lb.healthCheck.expectedCode {
		lb.markBackendUnhealthy(backend, fmt.Sprintf("Health check returned status %d, expected %d", resp.StatusCode, lb.healthCheck.expectedCode))
		return
	}

	// Backend is healthy
	backend.mu.Lock()
	wasUnhealthy := !backend.Healthy
	backend.Healthy = true
	backend.Failures = 0
	backend.mu.Unlock()

	if wasUnhealthy {
		log.Printf("Backend %s is now healthy", backend.ID)
		lb.metrics.LoadBalancerBackendStatus.WithLabelValues(backend.ID, "healthy").Set(1)
		lb.metrics.LoadBalancerBackendStatus.WithLabelValues(backend.ID, "unhealthy").Set(0)
	}

	lb.metrics.LoadBalancerHealthChecks.WithLabelValues(backend.ID, "success").Inc()
}

// markBackendUnhealthy marks a backend as unhealthy
func (lb *LoadBalancer) markBackendUnhealthy(backend *Backend, reason string) {
	backend.mu.Lock()
	wasHealthy := backend.Healthy
	backend.Healthy = false
	backend.Failures++
	backend.mu.Unlock()

	if wasHealthy {
		log.Printf("Backend %s marked as unhealthy: %s", backend.ID, reason)
		lb.metrics.LoadBalancerBackendStatus.WithLabelValues(backend.ID, "healthy").Set(0)
		lb.metrics.LoadBalancerBackendStatus.WithLabelValues(backend.ID, "unhealthy").Set(1)
	}

	lb.metrics.LoadBalancerHealthChecks.WithLabelValues(backend.ID, "failure").Inc()
}

// GetBackendStatus returns the status of all backends
func (lb *LoadBalancer) GetBackendStatus() map[string]interface{} {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	status := make(map[string]interface{})
	backends := make([]map[string]interface{}, len(lb.backends))

	for i, backend := range lb.backends {
		backend.mu.RLock()
		backends[i] = map[string]interface{}{
			"id":            backend.ID,
			"url":           backend.URL.String(),
			"weight":        backend.Weight,
			"healthy":       backend.Healthy,
			"connections":   backend.Connections,
			"last_check":    backend.LastCheck,
			"response_time": backend.ResponseTime.Milliseconds(),
			"failures":      backend.Failures,
		}
		backend.mu.RUnlock()
	}

	status["strategy"] = string(lb.strategy)
	status["backends"] = backends
	status["total_backends"] = len(lb.backends)
	status["healthy_backends"] = len(lb.getHealthyBackends())

	return status
}

// SetStrategy changes the load balancing strategy
func (lb *LoadBalancer) SetStrategy(strategy LoadBalancingStrategy) {
	lb.mu.Lock()
	lb.strategy = strategy
	lb.mu.Unlock()
	log.Printf("Load balancing strategy changed to %s", strategy)
}

// Middleware returns a Gin middleware for load balancing
func (lb *LoadBalancer) Middleware() gin.HandlerFunc {
	return gin.WrapH(lb)
}

// Shutdown gracefully shuts down the load balancer
func (lb *LoadBalancer) Shutdown() error {
	log.Println("Shutting down load balancer...")
	lb.cancel()
	log.Println("Load balancer shutdown complete")
	return nil
}

// UpdateBackendWeight updates the weight of a backend
func (lb *LoadBalancer) UpdateBackendWeight(id string, weight int) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for _, backend := range lb.backends {
		if backend.ID == id {
			backend.Weight = weight
			log.Printf("Updated backend %s weight to %d", id, weight)
			return nil
		}
	}

	return fmt.Errorf("backend %s not found", id)
}

// GetMetrics returns load balancer metrics
func (lb *LoadBalancer) GetMetrics() map[string]interface{} {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	healthyCount := 0
	totalConnections := int64(0)

	for _, backend := range lb.backends {
		backend.mu.RLock()
		if backend.Healthy {
			healthyCount++
		}
		totalConnections += backend.Connections
		backend.mu.RUnlock()
	}

	return map[string]interface{}{
		"strategy":           string(lb.strategy),
		"total_backends":     len(lb.backends),
		"healthy_backends":   healthyCount,
		"total_connections": totalConnections,
		"uptime":            time.Since(time.Now()).String(), // This should be tracked properly
	}
}