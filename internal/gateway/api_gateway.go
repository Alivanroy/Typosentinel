package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"

	"github.com/typosentinel/typosentinel/internal/auth"
	"github.com/typosentinel/typosentinel/internal/loadbalancer"
	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// RouteType defines the type of route
type RouteType int

const (
	RouteTypeProxy RouteType = iota
	RouteTypeStatic
	RouteTypeRedirect
	RouteTypeWebSocket
)

func (rt RouteType) String() string {
	switch rt {
	case RouteTypeProxy:
		return "proxy"
	case RouteTypeStatic:
		return "static"
	case RouteTypeRedirect:
		return "redirect"
	case RouteTypeWebSocket:
		return "websocket"
	default:
		return "unknown"
	}
}

// AuthLevel defines the authentication level required
type AuthLevel int

const (
	AuthLevelNone AuthLevel = iota
	AuthLevelOptional
	AuthLevelRequired
	AuthLevelAdmin
)

func (al AuthLevel) String() string {
	switch al {
	case AuthLevelNone:
		return "none"
	case AuthLevelOptional:
		return "optional"
	case AuthLevelRequired:
		return "required"
	case AuthLevelAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

// Route represents a gateway route configuration
type Route struct {
	ID              string            `json:"id"`
	Path            string            `json:"path"`
	Method          string            `json:"method"`
	Type            RouteType         `json:"type"`
	Target          string            `json:"target"`
	AuthLevel       AuthLevel         `json:"auth_level"`
	RateLimit       *RateLimitConfig  `json:"rate_limit"`
	Timeout         time.Duration     `json:"timeout"`
	Retries         int               `json:"retries"`
	Headers         map[string]string `json:"headers"`
	Transformations []Transformation  `json:"transformations"`
	CacheConfig     *CacheConfig      `json:"cache_config"`
	Enabled         bool              `json:"enabled"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	Enabled     bool          `json:"enabled"`
	RPS         int           `json:"rps"`
	Burst       int           `json:"burst"`
	Window      time.Duration `json:"window"`
	KeyFunction string        `json:"key_function"` // "ip", "user", "api_key"
}

// CacheConfig defines caching configuration
type CacheConfig struct {
	Enabled bool          `json:"enabled"`
	TTL     time.Duration `json:"ttl"`
	Vary    []string      `json:"vary"`
}

// Transformation defines request/response transformations
type Transformation struct {
	Type   string                 `json:"type"`   // "header", "body", "query"
	Action string                 `json:"action"` // "add", "remove", "replace"
	Target string                 `json:"target"`
	Value  interface{}            `json:"value"`
	Config map[string]interface{} `json:"config"`
}

// APIGateway represents the main gateway
type APIGateway struct {
	routes         map[string]*Route
	loadBalancer   *loadbalancer.LoadBalancer
	authManager    *auth.AuthManager
	redis          *redis.Client
	metrics        *metrics.Metrics
	rateLimiters   map[string]*rate.Limiter
	proxies        map[string]*httputil.ReverseProxy
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.RWMutex
	rateLimitersMu sync.RWMutex
	proxiesMu      sync.RWMutex
	config         *GatewayConfig
	running        bool
}

// GatewayConfig holds gateway configuration
type GatewayConfig struct {
	Host                string        `json:"host"`
	Port                int           `json:"port"`
	TLSEnabled          bool          `json:"tls_enabled"`
	TLSCertFile         string        `json:"tls_cert_file"`
	TLSKeyFile          string        `json:"tls_key_file"`
	ReadTimeout         time.Duration `json:"read_timeout"`
	WriteTimeout        time.Duration `json:"write_timeout"`
	IdleTimeout         time.Duration `json:"idle_timeout"`
	MaxHeaderBytes      int           `json:"max_header_bytes"`
	CORSEnabled         bool          `json:"cors_enabled"`
	CORSOrigins         []string      `json:"cors_origins"`
	CORSMethods         []string      `json:"cors_methods"`
	CORSHeaders         []string      `json:"cors_headers"`
	DefaultRateLimit    *RateLimitConfig `json:"default_rate_limit"`
	DefaultTimeout      time.Duration `json:"default_timeout"`
	DefaultRetries      int           `json:"default_retries"`
	HealthCheckPath     string        `json:"health_check_path"`
	MetricsPath         string        `json:"metrics_path"`
	RedisKeyPrefix      string        `json:"redis_key_prefix"`
	RouteRefreshInterval time.Duration `json:"route_refresh_interval"`
}

// RequestContext holds request-specific context
type RequestContext struct {
	RequestID   string                 `json:"request_id"`
	UserID      string                 `json:"user_id"`
	APIKey      string                 `json:"api_key"`
	ClientIP    string                 `json:"client_ip"`
	UserAgent   string                 `json:"user_agent"`
	StartTime   time.Time              `json:"start_time"`
	Route       *Route                 `json:"route"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResponseMetrics holds response metrics
type ResponseMetrics struct {
	StatusCode   int           `json:"status_code"`
	ResponseTime time.Duration `json:"response_time"`
	ResponseSize int64         `json:"response_size"`
	CacheHit     bool          `json:"cache_hit"`
	Retries      int           `json:"retries"`
}

// NewAPIGateway creates a new API gateway
func NewAPIGateway(config *GatewayConfig, loadBalancer *loadbalancer.LoadBalancer, authManager *auth.AuthManager, redis *redis.Client) *APIGateway {
	ctx, cancel := context.WithCancel(context.Background())

	// Set default values
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 30 * time.Second
	}
	if config.DefaultRetries == 0 {
		config.DefaultRetries = 3
	}
	if config.HealthCheckPath == "" {
		config.HealthCheckPath = "/health"
	}
	if config.MetricsPath == "" {
		config.MetricsPath = "/metrics"
	}
	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "typosentinel:gateway:"
	}
	if config.RouteRefreshInterval == 0 {
		config.RouteRefreshInterval = 30 * time.Second
	}

	return &APIGateway{
		routes:       make(map[string]*Route),
		loadBalancer: loadBalancer,
		authManager:  authManager,
		redis:        redis,
		metrics:      metrics.GetInstance(),
		rateLimiters: make(map[string]*rate.Limiter),
		proxies:      make(map[string]*httputil.ReverseProxy),
		ctx:          ctx,
		cancel:       cancel,
		config:       config,
	}
}

// Start starts the API gateway
func (gw *APIGateway) Start() error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.running {
		return fmt.Errorf("gateway is already running")
	}

	// Load routes from Redis
	if err := gw.loadRoutes(); err != nil {
		log.Printf("Failed to load routes: %v", err)
	}

	// Start route refresh routine
	go gw.routeRefreshRoutine()

	// Setup Gin router
	router := gw.setupRouter()

	// Start HTTP server
	server := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", gw.config.Host, gw.config.Port),
		Handler:        router,
		ReadTimeout:    gw.config.ReadTimeout,
		WriteTimeout:   gw.config.WriteTimeout,
		IdleTimeout:    gw.config.IdleTimeout,
		MaxHeaderBytes: gw.config.MaxHeaderBytes,
	}

	gw.running = true

	log.Printf("API Gateway starting on %s:%d", gw.config.Host, gw.config.Port)

	if gw.config.TLSEnabled {
		return server.ListenAndServeTLS(gw.config.TLSCertFile, gw.config.TLSKeyFile)
	}

	return server.ListenAndServe()
}

// setupRouter sets up the Gin router with middleware
func (gw *APIGateway) setupRouter() *gin.Engine {
	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(gw.corsMiddleware())
	router.Use(gw.requestContextMiddleware())
	router.Use(gw.rateLimitMiddleware())
	router.Use(gw.authMiddleware())
	router.Use(gw.metricsMiddleware())

	// Health check endpoint
	router.GET(gw.config.HealthCheckPath, gw.healthCheckHandler)

	// Metrics endpoint
	router.GET(gw.config.MetricsPath, gw.metricsHandler)

	// Catch-all route for dynamic routing
	router.NoRoute(gw.routeHandler)

	return router
}

// corsMiddleware handles CORS
func (gw *APIGateway) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !gw.config.CORSEnabled {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range gw.config.CORSOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Methods", strings.Join(gw.config.CORSMethods, ", "))
				c.Header("Access-Control-Allow-Headers", strings.Join(gw.config.CORSHeaders, ", "))
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// requestContextMiddleware creates request context
func (gw *APIGateway) requestContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqCtx := &RequestContext{
			RequestID: gw.generateRequestID(),
			ClientIP:  c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			StartTime: time.Now(),
			Metadata:  make(map[string]interface{}),
		}

		c.Set("request_context", reqCtx)
		c.Next()
	}
}

// rateLimitMiddleware handles rate limiting
func (gw *APIGateway) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqCtx := c.MustGet("request_context").(*RequestContext)

		// Find matching route
		route := gw.findRoute(c.Request.Method, c.Request.URL.Path)
		if route == nil {
			c.Next()
			return
		}

		reqCtx.Route = route

		// Check rate limit
		if route.RateLimit != nil && route.RateLimit.Enabled {
			key := gw.getRateLimitKey(route.RateLimit, reqCtx)
			limiter := gw.getRateLimiter(key, route.RateLimit)

			if !limiter.Allow() {
				gw.metrics.RateLimitExceeded.WithLabelValues(route.ID, key).Inc()
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded",
					"code":  "RATE_LIMIT_EXCEEDED",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// authMiddleware handles authentication
func (gw *APIGateway) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqCtx := c.MustGet("request_context").(*RequestContext)

		if reqCtx.Route == nil {
			c.Next()
			return
		}

		// Check authentication requirements
		switch reqCtx.Route.AuthLevel {
		case AuthLevelNone:
			// No authentication required
			break
		case AuthLevelOptional:
			// Try to authenticate but don't fail if not authenticated
			gw.tryAuthenticate(c, reqCtx)
		case AuthLevelRequired, AuthLevelAdmin:
			// Authentication required
			if !gw.authenticate(c, reqCtx) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "Authentication required",
					"code":  "UNAUTHORIZED",
				})
				c.Abort()
				return
			}

			// Check admin privileges if required
			if reqCtx.Route.AuthLevel == AuthLevelAdmin {
				if !gw.checkAdminPrivileges(reqCtx) {
					c.JSON(http.StatusForbidden, gin.H{
						"error": "Admin privileges required",
						"code":  "FORBIDDEN",
					})
					c.Abort()
					return
				}
			}
		}

		c.Next()
	}
}

// metricsMiddleware collects metrics
func (gw *APIGateway) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		reqCtx := c.MustGet("request_context").(*RequestContext)
		duration := time.Since(start)

		// Record metrics
		if reqCtx.Route != nil {
			gw.metrics.RequestDuration.WithLabelValues(
				reqCtx.Route.ID,
				c.Request.Method,
				strconv.Itoa(c.Writer.Status()),
			).Observe(duration.Seconds())

			gw.metrics.RequestCount.WithLabelValues(
				reqCtx.Route.ID,
				c.Request.Method,
				strconv.Itoa(c.Writer.Status()),
			).Inc()
		}

		// Log request
		log.Printf("[%s] %s %s %d %v",
			reqCtx.RequestID,
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			duration,
		)
	}
}

// routeHandler handles dynamic routing
func (gw *APIGateway) routeHandler(c *gin.Context) {
	reqCtx := c.MustGet("request_context").(*RequestContext)

	if reqCtx.Route == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Route not found",
			"code":  "ROUTE_NOT_FOUND",
		})
		return
	}

	// Apply transformations
	gw.applyTransformations(c, reqCtx.Route.Transformations)

	// Handle based on route type
	switch reqCtx.Route.Type {
	case RouteTypeProxy:
		gw.handleProxy(c, reqCtx)
	case RouteTypeStatic:
		gw.handleStatic(c, reqCtx)
	case RouteTypeRedirect:
		gw.handleRedirect(c, reqCtx)
	case RouteTypeWebSocket:
		gw.handleWebSocket(c, reqCtx)
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unsupported route type",
			"code":  "UNSUPPORTED_ROUTE_TYPE",
		})
	}
}

// handleProxy handles proxy requests
func (gw *APIGateway) handleProxy(c *gin.Context, reqCtx *RequestContext) {
	proxy := gw.getOrCreateProxy(reqCtx.Route)

	// Set additional headers
	for key, value := range reqCtx.Route.Headers {
		c.Request.Header.Set(key, value)
	}

	// Add request context headers
	c.Request.Header.Set("X-Request-ID", reqCtx.RequestID)
	c.Request.Header.Set("X-Client-IP", reqCtx.ClientIP)
	if reqCtx.UserID != "" {
		c.Request.Header.Set("X-User-ID", reqCtx.UserID)
	}

	// Serve the proxy request
	proxy.ServeHTTP(c.Writer, c.Request)
}

// handleStatic handles static content
func (gw *APIGateway) handleStatic(c *gin.Context, reqCtx *RequestContext) {
	// Serve static files from the target directory
	http.ServeFile(c.Writer, c.Request, reqCtx.Route.Target)
}

// handleRedirect handles redirects
func (gw *APIGateway) handleRedirect(c *gin.Context, reqCtx *RequestContext) {
	c.Redirect(http.StatusFound, reqCtx.Route.Target)
}

// handleWebSocket handles WebSocket connections
func (gw *APIGateway) handleWebSocket(c *gin.Context, reqCtx *RequestContext) {
	// TODO: Implement WebSocket proxying
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "WebSocket proxying not implemented",
		"code":  "NOT_IMPLEMENTED",
	})
}

// healthCheckHandler handles health check requests
func (gw *APIGateway) healthCheckHandler(c *gin.Context) {
	health := gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"routes":    len(gw.routes),
	}

	c.JSON(http.StatusOK, health)
}

// metricsHandler handles metrics requests
func (gw *APIGateway) metricsHandler(c *gin.Context) {
	// Return basic metrics
	metrics := gin.H{
		"routes":        len(gw.routes),
		"rate_limiters": len(gw.rateLimiters),
		"proxies":       len(gw.proxies),
		"uptime":        time.Since(time.Now()), // TODO: Track actual uptime
	}

	c.JSON(http.StatusOK, metrics)
}

// findRoute finds a matching route for the given method and path
func (gw *APIGateway) findRoute(method, path string) *Route {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	// Simple path matching - in production, use a more sophisticated router
	for _, route := range gw.routes {
		if !route.Enabled {
			continue
		}

		if route.Method == "*" || route.Method == method {
			if gw.pathMatches(route.Path, path) {
				return route
			}
		}
	}

	return nil
}

// pathMatches checks if a route path matches the request path
func (gw *APIGateway) pathMatches(routePath, requestPath string) bool {
	// Simple prefix matching - in production, use pattern matching
	if routePath == "*" {
		return true
	}

	if strings.HasSuffix(routePath, "*") {
		prefix := strings.TrimSuffix(routePath, "*")
		return strings.HasPrefix(requestPath, prefix)
	}

	return routePath == requestPath
}

// getRateLimitKey generates a rate limit key
func (gw *APIGateway) getRateLimitKey(config *RateLimitConfig, reqCtx *RequestContext) string {
	switch config.KeyFunction {
	case "user":
		if reqCtx.UserID != "" {
			return fmt.Sprintf("user:%s", reqCtx.UserID)
		}
		fallthrough
	case "api_key":
		if reqCtx.APIKey != "" {
			return fmt.Sprintf("api_key:%s", reqCtx.APIKey)
		}
		fallthrough
	default: // "ip"
		return fmt.Sprintf("ip:%s", reqCtx.ClientIP)
	}
}

// getRateLimiter gets or creates a rate limiter
func (gw *APIGateway) getRateLimiter(key string, config *RateLimitConfig) *rate.Limiter {
	gw.rateLimitersMu.Lock()
	defer gw.rateLimitersMu.Unlock()

	limiter, exists := gw.rateLimiters[key]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(config.RPS), config.Burst)
		gw.rateLimiters[key] = limiter
	}

	return limiter
}

// getOrCreateProxy gets or creates a reverse proxy
func (gw *APIGateway) getOrCreateProxy(route *Route) *httputil.ReverseProxy {
	gw.proxiesMu.Lock()
	defer gw.proxiesMu.Unlock()

	proxy, exists := gw.proxies[route.ID]
	if !exists {
		target, err := url.Parse(route.Target)
		if err != nil {
			log.Printf("Invalid target URL for route %s: %v", route.ID, err)
			return nil
		}

		proxy = httputil.NewSingleHostReverseProxy(target)
		proxy.Timeout = route.Timeout

		// Custom error handler
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for route %s: %v", route.ID, err)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("Bad Gateway"))
		}

		gw.proxies[route.ID] = proxy
	}

	return proxy
}

// tryAuthenticate attempts to authenticate without failing
func (gw *APIGateway) tryAuthenticate(c *gin.Context, reqCtx *RequestContext) {
	gw.authenticate(c, reqCtx)
}

// authenticate performs authentication
func (gw *APIGateway) authenticate(c *gin.Context, reqCtx *RequestContext) bool {
	// Check for API key
	apiKey := c.GetHeader("X-API-Key")
	if apiKey != "" {
		reqCtx.APIKey = apiKey
		// TODO: Validate API key
		return true
	}

	// Check for JWT token
	authorization := c.GetHeader("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") {
		token := strings.TrimPrefix(authorization, "Bearer ")
		if gw.authManager != nil {
			// TODO: Validate JWT token and extract user ID
			_ = token
			reqCtx.UserID = "user123" // Placeholder
			return true
		}
	}

	return false
}

// checkAdminPrivileges checks if the user has admin privileges
func (gw *APIGateway) checkAdminPrivileges(reqCtx *RequestContext) bool {
	// TODO: Implement admin privilege checking
	return reqCtx.UserID != ""
}

// applyTransformations applies request/response transformations
func (gw *APIGateway) applyTransformations(c *gin.Context, transformations []Transformation) {
	for _, transform := range transformations {
		switch transform.Type {
		case "header":
			gw.applyHeaderTransformation(c, transform)
		case "query":
			gw.applyQueryTransformation(c, transform)
			// TODO: Implement body transformations
		}
	}
}

// applyHeaderTransformation applies header transformations
func (gw *APIGateway) applyHeaderTransformation(c *gin.Context, transform Transformation) {
	switch transform.Action {
	case "add":
		c.Request.Header.Set(transform.Target, fmt.Sprintf("%v", transform.Value))
	case "remove":
		c.Request.Header.Del(transform.Target)
	case "replace":
		c.Request.Header.Set(transform.Target, fmt.Sprintf("%v", transform.Value))
	}
}

// applyQueryTransformation applies query parameter transformations
func (gw *APIGateway) applyQueryTransformation(c *gin.Context, transform Transformation) {
	query := c.Request.URL.Query()

	switch transform.Action {
	case "add":
		query.Set(transform.Target, fmt.Sprintf("%v", transform.Value))
	case "remove":
		query.Del(transform.Target)
	case "replace":
		query.Set(transform.Target, fmt.Sprintf("%v", transform.Value))
	}

	c.Request.URL.RawQuery = query.Encode()
}

// generateRequestID generates a unique request ID
func (gw *APIGateway) generateRequestID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), gw.getRandomInt())
}

// getRandomInt generates a random integer
func (gw *APIGateway) getRandomInt() int {
	// Simple random number generation - use crypto/rand in production
	return int(time.Now().UnixNano() % 1000000)
}

// loadRoutes loads routes from Redis
func (gw *APIGateway) loadRoutes() error {
	if gw.redis == nil {
		return nil
	}

	pattern := gw.config.RedisKeyPrefix + "routes:*"
	keys, err := gw.redis.Keys(gw.ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get route keys: %w", err)
	}

	for _, key := range keys {
		routeData, err := gw.redis.Get(gw.ctx, key).Result()
		if err != nil {
			log.Printf("Failed to get route data for key %s: %v", key, err)
			continue
		}

		var route Route
		if err := json.Unmarshal([]byte(routeData), &route); err != nil {
			log.Printf("Failed to unmarshal route data: %v", err)
			continue
		}

		gw.routes[route.ID] = &route
	}

	log.Printf("Loaded %d routes from Redis", len(gw.routes))
	return nil
}

// routeRefreshRoutine periodically refreshes routes from Redis
func (gw *APIGateway) routeRefreshRoutine() {
	ticker := time.NewTicker(gw.config.RouteRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := gw.loadRoutes(); err != nil {
				log.Printf("Failed to refresh routes: %v", err)
			}
		case <-gw.ctx.Done():
			return
		}
	}
}

// AddRoute adds a new route
func (gw *APIGateway) AddRoute(route *Route) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	// Set timestamps
	now := time.Now()
	if route.CreatedAt.IsZero() {
		route.CreatedAt = now
	}
	route.UpdatedAt = now

	// Set defaults
	if route.Timeout == 0 {
		route.Timeout = gw.config.DefaultTimeout
	}
	if route.Retries == 0 {
		route.Retries = gw.config.DefaultRetries
	}
	if route.Headers == nil {
		route.Headers = make(map[string]string)
	}

	gw.routes[route.ID] = route

	// Store in Redis
	if gw.redis != nil {
		go gw.storeRouteInRedis(route)
	}

	log.Printf("Added route: %s %s -> %s", route.Method, route.Path, route.Target)
	return nil
}

// RemoveRoute removes a route
func (gw *APIGateway) RemoveRoute(routeID string) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	delete(gw.routes, routeID)

	// Remove from Redis
	if gw.redis != nil {
		go gw.deleteRouteFromRedis(routeID)
	}

	// Clean up proxy
	gw.proxiesMu.Lock()
	delete(gw.proxies, routeID)
	gw.proxiesMu.Unlock()

	log.Printf("Removed route: %s", routeID)
	return nil
}

// GetRoute gets a route by ID
func (gw *APIGateway) GetRoute(routeID string) (*Route, bool) {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	route, exists := gw.routes[routeID]
	return route, exists
}

// GetAllRoutes returns all routes
func (gw *APIGateway) GetAllRoutes() map[string]*Route {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	routes := make(map[string]*Route)
	for id, route := range gw.routes {
		routes[id] = route
	}

	return routes
}

// storeRouteInRedis stores a route in Redis
func (gw *APIGateway) storeRouteInRedis(route *Route) {
	key := gw.config.RedisKeyPrefix + "routes:" + route.ID
	data, err := json.Marshal(route)
	if err != nil {
		log.Printf("Failed to marshal route: %v", err)
		return
	}

	if err := gw.redis.Set(gw.ctx, key, data, 0).Err(); err != nil {
		log.Printf("Failed to store route in Redis: %v", err)
	}
}

// deleteRouteFromRedis deletes a route from Redis
func (gw *APIGateway) deleteRouteFromRedis(routeID string) {
	key := gw.config.RedisKeyPrefix + "routes:" + routeID
	if err := gw.redis.Del(gw.ctx, key).Err(); err != nil {
		log.Printf("Failed to delete route from Redis: %v", err)
	}
}

// Shutdown gracefully shuts down the gateway
func (gw *APIGateway) Shutdown() error {
	log.Println("Shutting down API Gateway...")
	gw.cancel()
	gw.running = false
	log.Println("API Gateway shutdown complete")
	return nil
}

// IsRunning returns whether the gateway is running
func (gw *APIGateway) IsRunning() bool {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.running
}