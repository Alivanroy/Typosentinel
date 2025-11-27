// Package main implements the TypoSentinel demo API server and endpoints.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"bytes"
	"net/smtp"

	apimetrics "github.com/Alivanroy/Typosentinel/internal/api/metrics"
	apilm "github.com/Alivanroy/Typosentinel/internal/api/middleware"
	appcfg "github.com/Alivanroy/Typosentinel/internal/config"
	pkgmetrics "github.com/Alivanroy/Typosentinel/pkg/metrics"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	redis "github.com/redis/go-redis/v9"
	"github.com/rs/cors"
	"golang.org/x/time/rate"
)

type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

type ReadyResponse struct {
	Ready     bool      `json:"ready"`
	Timestamp time.Time `json:"timestamp"`
}

type TestResponse struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type AnalyzeRequest struct {
	PackageName string `json:"package_name"`
	Registry    string `json:"registry,omitempty"`
}

type AnalysisResult struct {
	PackageName string    `json:"package_name"`
	Registry    string    `json:"registry"`
	Threats     []Threat  `json:"threats"`
	Warnings    []Warning `json:"warnings"`
	RiskLevel   int       `json:"risk_level"`
	RiskScore   float64   `json:"risk_score"`
	AnalyzedAt  time.Time `json:"analyzed_at"`
}

type Threat struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

type Warning struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type BatchAnalyzeRequest struct {
	Packages []AnalyzeRequest `json:"packages"`
}

type BatchAnalysisResult struct {
	Results    []AnalysisResult `json:"results"`
	Summary    BatchSummary     `json:"summary"`
	AnalyzedAt time.Time        `json:"analyzed_at"`
}

type BatchSummary struct {
	Total      int `json:"total"`
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	LowRisk    int `json:"low_risk"`
	NoThreats  int `json:"no_threats"`
}

// Rate limiter for API endpoints
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check pattern
		if limiter, exists = rl.limiters[ip]; !exists {
			// Allow 10 requests per minute for demo
			limiter = rate.NewLimiter(rate.Every(6*time.Second), 10)
			rl.limiters[ip] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}

// Global instances
var (
	rateLimiter *RateLimiter
)

// API key authentication middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/test" {
			next(w, r)
			return
		}

		enabled := os.Getenv("API_AUTH_ENABLED")
		if strings.EqualFold(enabled, "false") || enabled == "0" {
			next(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing Authorization header"})
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Authorization format"})
			return
		}
		token := parts[1]
		if !validateAPIKey(token) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid API key"})
			return
		}
		next(w, r)
	}
}

func validateAPIKey(token string) bool {
	keys := os.Getenv("API_KEYS")
	if keys == "" {
		return false
	}
	for _, k := range strings.Split(keys, ",") {
		key := strings.TrimSpace(k)
		if subtle.ConstantTimeCompare([]byte(key), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}
	json.NewEncoder(w).Encode(response)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")

	// Redis readiness: prefer internal config; fall back to env DSN
	cfgMgr := appcfg.NewManager()
	_ = cfgMgr.Load(".")
	cfg := cfgMgr.Get()
	var redisDSN string
	var redisConfigured bool
	if cfg != nil && cfg.Redis.Enabled {
		if cfg.Redis.Password != "" {
			redisDSN = fmt.Sprintf("redis://:%s@%s:%d/%d", cfg.Redis.Password, cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Database)
		} else {
			redisDSN = fmt.Sprintf("redis://%s:%d/%d", cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Database)
		}
		redisConfigured = true
	} else {
		redisDSN = os.Getenv("RATE_LIMIT_REDIS_URL")
		redisConfigured = redisDSN != ""
	}
	redisOK := false
	if redisConfigured {
		if opt, err := redis.ParseURL(redisDSN); err == nil {
			c := redis.NewClient(opt)
			if c.Ping(r.Context()).Err() == nil {
				redisOK = true
			}
		}
		apimetrics.SetRedisConnected(redisOK)
	}

	// Webhook providers readiness via env secrets
	providers := map[string]string{
		"github":    os.Getenv("GITHUB_WEBHOOK_SECRET"),
		"gitlab":    os.Getenv("GITLAB_WEBHOOK_TOKEN"),
		"bitbucket": os.Getenv("BITBUCKET_WEBHOOK_SECRET"),
		"azure":     os.Getenv("AZURE_WEBHOOK_SECRET"),
	}
	webhooks := make(map[string]map[string]bool)
	for p, secret := range providers {
		configured := secret != ""
		apimetrics.SetWebhookProviderEnabled(p, configured)
		apimetrics.SetWebhookProviderSignatureConfigured(p, configured)
		webhooks[p] = map[string]bool{"configured": configured}
	}

	ready := true
	if redisConfigured && !redisOK {
		ready = false
	}

	resp := map[string]interface{}{
		"ready":     ready,
		"timestamp": time.Now(),
		"redis": map[string]interface{}{
			"configured": redisConfigured,
			"connected":  redisOK,
		},
		"webhooks": webhooks,
	}

	json.NewEncoder(w).Encode(resp)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")
	response := TestResponse{
		Message:   "test endpoint working",
		Timestamp: time.Now(),
	}
	json.NewEncoder(w).Encode(response)
}

// Rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !rateLimiter.Allow(ip) {
			apimetrics.RecordRateLimitHit(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests. Please try again later.",
				"retry_after": "60 seconds",
			})
			return
		}
		next(w, r)
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.PackageName == "" {
		http.Error(w, "Package name is required", http.StatusBadRequest)
		return
	}
	if req.Registry == "" {
		req.Registry = "npm" // Default to npm
	}

	if err := validatePackageInput(req.PackageName, req.Registry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Perform simplified threat analysis for demo
	threats, warnings := performThreatAnalysis(req.PackageName, req.Registry)

	// Calculate risk level and score
	riskLevel, riskScore := calculateRiskLevel(threats)

	// Create response
	result := AnalysisResult{
		PackageName: req.PackageName,
		Registry:    req.Registry,
		Threats:     threats,
		Warnings:    warnings,
		RiskLevel:   riskLevel,
		RiskScore:   riskScore,
		AnalyzedAt:  time.Now(),
	}

	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	if result.RiskLevel >= 3 {
		if url := os.Getenv("SLACK_WEBHOOK_URL"); url != "" {
			payload := map[string]interface{}{"text": fmt.Sprintf("High risk detected: %s (%s) risk=%d", result.PackageName, result.Registry, result.RiskLevel)}
			b, _ := json.Marshal(payload)
			_, _ = http.Post(url, "application/json", bytes.NewBuffer(b))
		}
		host := os.Getenv("SMTP_HOST")
		user := os.Getenv("SMTP_USER")
		pass := os.Getenv("SMTP_PASS")
		to := os.Getenv("EMAIL_TO")
		from := os.Getenv("EMAIL_FROM")
		if host != "" && user != "" && pass != "" && to != "" && from != "" {
			msg := []byte("Subject: TypoSentinel Alert\r\n\r\n" + fmt.Sprintf("High risk detected: %s (%s) risk=%d", result.PackageName, result.Registry, result.RiskLevel))
			_ = smtp.SendMail(host+":587", smtp.PlainAuth("", user, pass, host), from, []string{to}, msg)
		}
	}
}

func batchAnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BatchAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if len(req.Packages) == 0 {
		http.Error(w, "At least one package is required", http.StatusBadRequest)
		return
	}

	// Limit batch size for demo
	if len(req.Packages) > 10 {
		http.Error(w, "Maximum 10 packages allowed per batch", http.StatusBadRequest)
		return
	}

	// Analyze each package
	var results []AnalysisResult
	summary := BatchSummary{}

	for _, pkg := range req.Packages {
		// Set default registry if not provided
		if pkg.Registry == "" {
			pkg.Registry = "npm"
		}

		if err := validatePackageInput(pkg.PackageName, pkg.Registry); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Perform threat analysis
		threats, warnings := performThreatAnalysis(pkg.PackageName, pkg.Registry)

		// Calculate risk level and score
		riskLevel, riskScore := calculateRiskLevel(threats)

		// Create result
		result := AnalysisResult{
			PackageName: pkg.PackageName,
			Registry:    pkg.Registry,
			Threats:     threats,
			Warnings:    warnings,
			RiskLevel:   riskLevel,
			RiskScore:   riskScore,
			AnalyzedAt:  time.Now(),
		}

		results = append(results, result)

		// Update summary
		summary.Total++
		switch riskLevel {
		case 3:
			summary.HighRisk++
		case 2:
			summary.MediumRisk++
		case 1:
			summary.LowRisk++
		default:
			summary.NoThreats++
		}
	}

	// Create batch response
	batchResult := BatchAnalysisResult{
		Results:    results,
		Summary:    summary,
		AnalyzedAt: time.Now(),
	}

	if err := json.NewEncoder(w).Encode(batchResult); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Helper functions for threat analysis
func performThreatAnalysis(packageName, registry string) ([]Threat, []Warning) {
	var threats []Threat
	var warnings []Warning

	// Demo threat analysis - in real implementation this would use ML models
	// Check for suspicious patterns
	if strings.Contains(packageName, "test") || strings.Contains(packageName, "demo") {
		threats = append(threats, Threat{
			Type:        "typosquatting",
			Severity:    "medium",
			Description: "Package name contains suspicious keywords",
			Confidence:  0.7,
		})
	}

	// Check for short package names (potential typosquatting)
	if len(packageName) <= 3 {
		warnings = append(warnings, Warning{
			Type:        "short_name",
			Description: "Very short package name - verify legitimacy",
		})
	}

	// Check for numbers in package name
	if strings.ContainsAny(packageName, "0123456789") {
		warnings = append(warnings, Warning{
			Type:        "numeric_chars",
			Description: "Package name contains numbers - common in typosquatting",
		})
	}

	return threats, warnings
}

func calculateRiskLevel(threats []Threat) (int, float64) {
	if len(threats) == 0 {
		return 0, 0.0
	}

	maxScore := 0.0
	for _, threat := range threats {
		if threat.Confidence > maxScore {
			maxScore = threat.Confidence
		}
	}

	if maxScore >= 0.8 {
		return 3, maxScore // High risk
	} else if maxScore >= 0.5 {
		return 2, maxScore // Medium risk
	} else if maxScore > 0 {
		return 1, maxScore // Low risk
	}
	return 0, 0.0 // No threats
}

// Input validation helpers
func validatePackageInput(name, registry string) error {
	if len(name) > 214 {
		return fmt.Errorf("Package name too long")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, ";&|`") {
		return fmt.Errorf("Invalid characters in package name")
	}
	switch registry {
	case "npm":
		if !npmValid(name) {
			return fmt.Errorf("Invalid npm package name")
		}
	case "pypi":
		if !pypiValid(name) {
			return fmt.Errorf("Invalid PyPI package name")
		}
	case "go":
		if !goValid(name) {
			return fmt.Errorf("Invalid Go package name")
		}
	case "maven":
		if !mavenValid(name) {
			return fmt.Errorf("Invalid Maven package name")
		}
	}
	return nil
}

func npmValid(name string) bool {
	n := strings.ToLower(name)
	return !strings.ContainsAny(n, " \t\n")
}

func pypiValid(name string) bool {
	if len(name) == 0 {
		return false
	}
	return isAlphaNum(name[0]) && isAlphaNum(name[len(name)-1])
}

func goValid(name string) bool {
	if strings.ContainsAny(name, " \t\n") {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return false
	}
	if !strings.Contains(name, "/") {
		return false
	}
	return true
}

func mavenValid(name string) bool {
	if strings.ContainsAny(name, " \t\n") {
		return false
	}
	parts := strings.Split(name, ":")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func main() {
	// Initialize rate limiter
	rateLimiter = NewRateLimiter()

	// Create router
	r := mux.NewRouter()

	// Prometheus and JSON metrics endpoints
	r.Use(apimetrics.PrometheusMiddleware())
	r.Handle("/metrics", promhttp.Handler()).Methods("GET")
	r.HandleFunc("/metrics.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		m := pkgmetrics.GetInstance()
		json.NewEncoder(w).Encode(m.GetMetrics())
	}).Methods("GET")

	// Health check endpoints
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/ready", readyHandler).Methods("GET")
	r.HandleFunc("/test", testHandler).Methods("GET")

	// API endpoints with auth and rate limiting
	if dsn := os.Getenv("RATE_LIMIT_REDIS_URL"); dsn != "" {
		if rl, err := apilm.NewRedisLimiter(dsn, apilm.RatePolicy{Limit: 10, Window: time.Minute}); err == nil {
			wrap := apilm.RateLimitMiddleware(rl, func(r *http.Request) string { return getClientIP(r) })
			r.Handle("/v1/analyze", wrap(authMiddleware(http.HandlerFunc(analyzeHandler)))).Methods("POST")
			r.Handle("/v1/analyze/batch", wrap(authMiddleware(http.HandlerFunc(batchAnalyzeHandler)))).Methods("POST")
		} else {
			r.Handle("/v1/analyze", rateLimitMiddleware(authMiddleware(http.HandlerFunc(analyzeHandler)))).Methods("POST")
			r.Handle("/v1/analyze/batch", rateLimitMiddleware(authMiddleware(http.HandlerFunc(batchAnalyzeHandler)))).Methods("POST")
		}
	} else {
		r.Handle("/v1/analyze", rateLimitMiddleware(authMiddleware(http.HandlerFunc(analyzeHandler)))).Methods("POST")
		r.Handle("/v1/analyze/batch", rateLimitMiddleware(authMiddleware(http.HandlerFunc(batchAnalyzeHandler)))).Methods("POST")
	}
	r.HandleFunc("/v1/status", statusHandler).Methods("GET")
	r.HandleFunc("/v1/stats", statsHandler).Methods("GET")
	r.HandleFunc("/api/v1/vulnerabilities", vulnerabilitiesHandler).Methods("GET")

	// Dashboard endpoints
	r.HandleFunc("/api/v1/dashboard/metrics", dashboardMetricsHandler).Methods("GET")
	r.HandleFunc("/api/v1/dashboard/performance", dashboardPerformanceHandler).Methods("GET")

	// Planned scans listing
	r.HandleFunc("/api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "This endpoint is planned for v1.1",
			"status": "not_implemented",
		})
	}).Methods("GET")

	// Configure CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000", "http://localhost:8080"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	// SSE stream for real-time monitoring (basic keepalive)
	r.HandleFunc("/v1/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for i := 0; i < 3; i++ {
			<-ticker.C
			fmt.Fprintf(w, "data: {\"type\": \"ping\", \"count\": %d}\n\n", i+1)
			flusher.Flush()
		}
	}).Methods("GET")

	// Wrap router with CORS
	handler := c.Handler(r)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("TypoSentinel API server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")
	status := map[string]interface{}{
		"service":   "TypoSentinel API",
		"version":   "1.0.0",
		"status":    "operational",
		"timestamp": time.Now(),
		"features": map[string]bool{
			"typosquatting_detection": true,
			"malware_scanning":        true,
			"reputation_analysis":     true,
			"homoglyph_detection":     true,
			"dependency_confusion":    true,
			"batch_analysis":          true,
			"rate_limiting":           true,
		},
		"limits": map[string]interface{}{
			"requests_per_minute": 10,
			"batch_size_limit":    10,
		},
	}
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")
	stats := map[string]interface{}{
		"total_requests":     "N/A (demo mode)",
		"packages_analyzed":  "N/A (demo mode)",
		"threats_detected":   "N/A (demo mode)",
		"uptime":             "N/A (demo mode)",
		"rate_limit_hits":    "N/A (demo mode)",
		"popular_ecosystems": []string{"npm", "pypi", "maven", "nuget"},
		"demo_mode":          true,
		"message":            "This is a demo API. Statistics are not tracked in demo mode.",
	}
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func vulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  "This endpoint is planned for v1.1",
		"status": "not_implemented",
	})
}

func dashboardMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  "This endpoint is planned for v1.1",
		"status": "not_implemented",
	})
}

func dashboardPerformanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  "This endpoint is planned for v1.1",
		"status": "not_implemented",
	})
}
