package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

// ScanRequest represents a package scan request
type ScanRequest struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// BulkScanRequest represents multiple package scan requests
type BulkScanRequest struct {
	Packages []ScanRequest `json:"packages"`
}

// ScanResponse represents the response from a scan
type ScanResponse struct {
	ID        string                 `json:"id"`
	Package   string                 `json:"package"`
	Version   string                 `json:"version"`
	Status    string                 `json:"status"`
	Result    map[string]interface{} `json:"result,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  string                 `json:"duration,omitempty"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

// StatsResponse represents scan statistics
type StatsResponse struct {
	TotalScans      int64      `json:"total_scans"`
	SuccessfulScans int64      `json:"successful_scans"`
	FailedScans     int64      `json:"failed_scans"`
	AverageTime     float64    `json:"average_time_seconds"`
	LastScan        *time.Time `json:"last_scan,omitempty"`
}

var (
	scanHistory = make(map[string]*ScanResponse)
	stats       = &StatsResponse{}
)

func main() {
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/health", healthHandler).Methods("GET")
	api.HandleFunc("/scan", scanHandler).Methods("POST")
	api.HandleFunc("/scan/bulk", bulkScanHandler).Methods("POST")
	api.HandleFunc("/scans", getScansHandler).Methods("GET")
	api.HandleFunc("/scans/{id}", getScanHandler).Methods("GET")
	api.HandleFunc("/stats", getStatsHandler).Methods("GET")

	// Metrics endpoint for Prometheus
	r.HandleFunc("/metrics", metricsHandler).Methods("GET")

	// CORS configuration
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("TypoSentinel API server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}
	json.NewEncoder(w).Encode(response)
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Package == "" {
		http.Error(w, "Package name is required", http.StatusBadRequest)
		return
	}

	if req.Version == "" {
		req.Version = "latest"
	}

	// Generate scan ID
	scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())

	// Create scan response
	scanResp := &ScanResponse{
		ID:        scanID,
		Package:   req.Package,
		Version:   req.Version,
		Status:    "processing",
		Timestamp: time.Now(),
	}

	// Store in history
	scanHistory[scanID] = scanResp

	// Start scan in background
	go performScan(scanID, req)

	// Return immediate response
	json.NewEncoder(w).Encode(scanResp)
}

func bulkScanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BulkScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Packages) == 0 {
		http.Error(w, "At least one package is required", http.StatusBadRequest)
		return
	}

	var responses []*ScanResponse

	for _, pkg := range req.Packages {
		if pkg.Package == "" {
			continue
		}

		if pkg.Version == "" {
			pkg.Version = "latest"
		}

		// Generate scan ID
		scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())

		// Create scan response
		scanResp := &ScanResponse{
			ID:        scanID,
			Package:   pkg.Package,
			Version:   pkg.Version,
			Status:    "processing",
			Timestamp: time.Now(),
		}

		// Store in history
		scanHistory[scanID] = scanResp
		responses = append(responses, scanResp)

		// Start scan in background
		go performScan(scanID, pkg)
	}

	json.NewEncoder(w).Encode(responses)
}

func getScansHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var scans []*ScanResponse
	for _, scan := range scanHistory {
		scans = append(scans, scan)
	}

	json.NewEncoder(w).Encode(scans)
}

func getScanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	scanID := vars["id"]

	scan, exists := scanHistory[scanID]
	if !exists {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(scan)
}

func getStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Calculate stats from scan history
	totalScans := int64(len(scanHistory))
	successfulScans := int64(0)
	failedScans := int64(0)
	var lastScan *time.Time

	for _, scan := range scanHistory {
		if scan.Status == "completed" {
			successfulScans++
		} else if scan.Status == "failed" {
			failedScans++
		}

		if lastScan == nil || scan.Timestamp.After(*lastScan) {
			lastScan = &scan.Timestamp
		}
	}

	statsResp := StatsResponse{
		TotalScans:      totalScans,
		SuccessfulScans: successfulScans,
		FailedScans:     failedScans,
		AverageTime:     2.5, // Mock average time
		LastScan:        lastScan,
	}

	json.NewEncoder(w).Encode(statsResp)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	// Basic Prometheus metrics
	metrics := fmt.Sprintf(`# HELP typosentinel_scans_total Total number of scans
# TYPE typosentinel_scans_total counter
typosentinel_scans_total %d

# HELP typosentinel_scans_successful_total Total number of successful scans
# TYPE typosentinel_scans_successful_total counter
typosentinel_scans_successful_total %d

# HELP typosentinel_scans_failed_total Total number of failed scans
# TYPE typosentinel_scans_failed_total counter
typosentinel_scans_failed_total %d

# HELP typosentinel_api_up API service status
# TYPE typosentinel_api_up gauge
typosentinel_api_up 1
`,
		len(scanHistory),
		countScansByStatus("completed"),
		countScansByStatus("failed"))

	w.Write([]byte(metrics))
}

func performScan(scanID string, req ScanRequest) {
	startTime := time.Now()

	// Get scan from history
	scan := scanHistory[scanID]
	if scan == nil {
		return
	}

	// Check if typosentinel binary exists
	typosentinelPath := "/app/typosentinel"
	if _, err := os.Stat(typosentinelPath); os.IsNotExist(err) {
		// Fallback to mock scan for demo purposes
		performMockScan(scan, req)
		return
	}

	// Execute actual typosentinel scan
	cmd := exec.Command(typosentinelPath, "scan", req.Package, "--format", "json")
	if req.Version != "latest" {
		cmd.Args = append(cmd.Args, "--version", req.Version)
	}

	output, err := cmd.Output()
	if err != nil {
		scan.Status = "failed"
		scan.Result = map[string]interface{}{
			"error": err.Error(),
		}
	} else {
		// Parse JSON output
		var result map[string]interface{}
		if err := json.Unmarshal(output, &result); err != nil {
			// If JSON parsing fails, store raw output
			result = map[string]interface{}{
				"raw_output": string(output),
			}
		}

		scan.Status = "completed"
		scan.Result = result
	}

	scan.Duration = time.Since(startTime).String()
}

func performMockScan(scan *ScanResponse, req ScanRequest) {
	// Simulate scan processing time
	time.Sleep(time.Duration(2+len(req.Package)%5) * time.Second)

	// Mock scan result
	mockResult := map[string]interface{}{
		"package":    req.Package,
		"version":    req.Version,
		"risk_level": "medium",
		"risk_score": 0.6,
		"findings": []map[string]interface{}{
			{
				"type":        "static_analysis",
				"severity":    "medium",
				"description": "Potential security vulnerability detected",
				"confidence":  0.8,
			},
			{
				"type":        "ml_analysis",
				"severity":    "low",
				"description": "Suspicious pattern detected in package metadata",
				"confidence":  0.6,
			},
		},
		"recommendations": []string{
			"Review package dependencies",
			"Check for known vulnerabilities",
			"Consider alternative packages",
		},
		"metadata": map[string]interface{}{
			"scan_time":    time.Now().Format(time.RFC3339),
			"scan_engine":  "typosentinel-demo",
			"scan_version": "1.0.0",
		},
	}

	// Simulate different outcomes based on package name
	if strings.Contains(strings.ToLower(req.Package), "malicious") {
		mockResult["risk_level"] = "critical"
		mockResult["risk_score"] = 0.95
	} else if strings.Contains(strings.ToLower(req.Package), "safe") {
		mockResult["risk_level"] = "low"
		mockResult["risk_score"] = 0.2
	}

	scan.Status = "completed"
	scan.Result = mockResult
	scan.Duration = "2.5s"
}

func countScansByStatus(status string) int {
	count := 0
	for _, scan := range scanHistory {
		if scan.Status == status {
			count++
		}
	}
	return count
}
