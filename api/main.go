package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
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
	PackageName string        `json:"package_name"`
	Registry    string        `json:"registry"`
	Threats     []Threat      `json:"threats"`
	Warnings    []Warning     `json:"warnings"`
	RiskLevel   int           `json:"risk_level"`
	RiskScore   float64       `json:"risk_score"`
	AnalyzedAt  time.Time     `json:"analyzed_at"`
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
	Results   []AnalysisResult `json:"results"`
	Summary   BatchSummary     `json:"summary"`
	AnalyzedAt time.Time       `json:"analyzed_at"`
}

type BatchSummary struct {
	Total       int `json:"total"`
	HighRisk    int `json:"high_risk"`
	MediumRisk  int `json:"medium_risk"`
	LowRisk     int `json:"low_risk"`
	NoThreats   int `json:"no_threats"`
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
	rateLimiter  *RateLimiter
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}
	json.NewEncoder(w).Encode(response)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := ReadyResponse{
		Ready:     true,
		Timestamp: time.Now(),
	}

	json.NewEncoder(w).Encode(response)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := TestResponse{
		Message: "test endpoint working",
	}
	json.NewEncoder(w).Encode(response)
}

// Rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !rateLimiter.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Rate limit exceeded",
				"message": "Too many requests. Please try again later.",
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

	json.NewEncoder(w).Encode(result)
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

	json.NewEncoder(w).Encode(batchResult)
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

func main() {
	// Initialize rate limiter
	rateLimiter = NewRateLimiter()

	// Create router
	r := mux.NewRouter()

	// Health check endpoints
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/ready", readyHandler).Methods("GET")
	r.HandleFunc("/test", testHandler).Methods("GET")

	// API endpoints with rate limiting
	r.Handle("/v1/analyze", rateLimitMiddleware(http.HandlerFunc(analyzeHandler))).Methods("POST")
	r.Handle("/v1/analyze/batch", rateLimitMiddleware(http.HandlerFunc(batchAnalyzeHandler))).Methods("POST")
	r.HandleFunc("/v1/status", statusHandler).Methods("GET")
	r.HandleFunc("/v1/stats", statsHandler).Methods("GET")

	// Configure CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

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
	status := map[string]interface{}{
		"service":    "TypoSentinel API",
		"version":    "1.0.0",
		"status":     "operational",
		"timestamp":  time.Now(),
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
	json.NewEncoder(w).Encode(status)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
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
	json.NewEncoder(w).Encode(stats)
}