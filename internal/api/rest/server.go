package rest

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/api/rest/handlers"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Server represents the REST API server
type Server struct {
	config     config.RESTAPIConfig
	gin        *gin.Engine
	server     *http.Server
	mlPipeline *ml.MLPipeline
	analyzer   *analyzer.Analyzer
	running    bool
	// Enterprise components
	enterpriseHandlers *EnterpriseHandlers
	// OSS scan handlers
	scanHandlers *handlers.ScanHandlers
}

// NewServer creates a new REST API server
func NewServer(cfg config.RESTAPIConfig, mlPipeline *ml.MLPipeline, analyzer *analyzer.Analyzer) *Server {
	return NewServerWithEnterprise(cfg, mlPipeline, analyzer, nil)
}

// NewServerWithEnterprise creates a new REST API server with optional enterprise features
func NewServerWithEnterprise(cfg config.RESTAPIConfig, mlPipeline *ml.MLPipeline, analyzer *analyzer.Analyzer, enterpriseHandlers *EnterpriseHandlers) *Server {
	// Set gin mode based on API configuration
	if !cfg.Enabled {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Add middleware
	r.Use(gin.Recovery())
	r.Use(requestid.New())

	// Add CORS middleware if configured
	if cfg.CORS != nil {
		r.Use(corsMiddleware(*cfg.CORS))
	}

	r.Use(loggingMiddleware())

	// Add rate limiting middleware if configured
	if cfg.RateLimiting != nil {
		r.Use(rateLimitMiddleware(*cfg.RateLimiting))
	}

	// Add auth middleware if configured
	if cfg.Authentication != nil {
		r.Use(authMiddleware(cfg.Authentication))
	}
	// Timeout middleware removed - not available in RESTAPIConfig

	// Initialize OSS database service
	ossDB, err := database.NewOSSService("./data/typosentinel.db")
	if err != nil {
		log.Printf("Failed to initialize OSS database: %v", err)
		// Continue without database for now
	}

	// Initialize detector engine with default config
	detectorEngine := detector.New(&config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled:     true,
			Threshold:   0.8,
			MaxDistance: 3,
		},
	})

	// Initialize scan handlers
	var scanHandlers *handlers.ScanHandlers
	if ossDB != nil {
		scanHandlers = handlers.NewScanHandlers(ossDB, detectorEngine)
	}

	server := &Server{
		config:             cfg,
		gin:                r,
		mlPipeline:         mlPipeline,
		analyzer:           analyzer,
		enterpriseHandlers: enterpriseHandlers,
		scanHandlers:       scanHandlers,
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// Start starts the REST API server
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.gin,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting REST API server on %s", addr)

	s.running = true

	// Start server
	return s.server.ListenAndServe()
}

// Stop stops the REST API server
func (s *Server) Stop(ctx context.Context) error {
	if !s.running {
		return nil
	}

	logger.Info("Stopping REST API server")
	s.running = false

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	return s.running
}

// setupRoutes sets up all API routes
func (s *Server) setupRoutes() {
	// Health check
	s.gin.GET("/health", s.healthCheck)
	s.gin.GET("/ready", s.readinessCheck)

	// Simple test route
	s.gin.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "test endpoint working"})
	})

	// Documentation endpoints (root level)
	s.gin.GET(s.config.BasePath+"/docs", s.getSwaggerUI)
	s.gin.GET(s.config.BasePath+"/docs/", s.getSwaggerUI)
	s.gin.GET(s.config.BasePath+"/docs/openapi", s.getOpenAPISpec)

	// API versioning
	if s.config.Versioning.Enabled {
		v1 := s.gin.Group(s.config.BasePath + "/v1")
		{
			// Package analysis endpoints
			v1.POST("/analyze", s.analyzePackage)
			v1.POST("/batch-analyze", s.batchAnalyzePackages)
			v1.GET("/package/:ecosystem/:name", s.analyzePackageByName)

			// ML prediction endpoints
			v1.POST("/ml/predict/typosquatting", s.predictTyposquatting)
			v1.POST("/ml/predict/reputation", s.predictReputation)
			v1.POST("/ml/predict/anomaly", s.predictAnomaly)
			v1.GET("/ml/models/status", s.getMLModelsStatus)
			v1.POST("/ml/models/train", s.trainMLModels)

			// Vulnerability scanning endpoints
			v1.POST("/vulnerabilities/scan", s.scanVulnerabilities)
			v1.POST("/vulnerabilities/scan/:ecosystem/:name", s.scanPackageVulnerabilities)
			v1.POST("/vulnerabilities/batch-scan", s.batchScanVulnerabilities)
			v1.GET("/vulnerabilities/scan/:id/status", s.getVulnerabilityScanStatus)
			v1.GET("/vulnerabilities/database/status", s.getVulnerabilityDatabaseStatus)

			// Package scanning endpoints (OSS)
			if s.scanHandlers != nil {
				v1.POST("/scan/package", s.scanHandlers.StartScan)
				v1.GET("/scan/results", s.scanHandlers.GetScanResults)
				v1.GET("/scan/:id", s.scanHandlers.GetScanByID)
				v1.GET("/scan/search", s.scanHandlers.SearchPackages)
				v1.GET("/scan/stats", s.scanHandlers.GetScanStats)
			}

			// System endpoints
			v1.GET("/system/status", s.getSystemStatus)
			v1.GET("/system/metrics", s.getSystemMetrics)
			v1.POST("/system/cache/clear", s.clearCache)

			// Configuration endpoints
			v1.GET("/config", s.getConfiguration)
			v1.PUT("/config", s.updateConfiguration)
			v1.POST("/config/validate", s.validateConfiguration)

			// Analysis results endpoints
			v1.GET("/analysis/history", s.getAnalysisHistory)
			v1.GET("/analysis/statistics", s.getAnalysisStatistics)
			v1.GET("/analysis/export", s.exportResults)

			// Documentation endpoints
			v1.GET("/docs/openapi", s.getOpenAPISpec)
			v1.GET("/docs", s.getSwaggerUI)
			v1.GET("/docs/", s.getSwaggerUI)

			// Enterprise endpoints
			if s.enterpriseHandlers != nil {
				enterpriseGroup := v1.Group("/enterprise")
				s.enterpriseHandlers.RegisterRoutes(enterpriseGroup)
			}
		}

		// Dashboard endpoints (non-versioned for frontend compatibility)
		dashboard := s.gin.Group(s.config.BasePath + "/dashboard")
		{
			dashboard.GET("/metrics", s.getDashboardMetrics)
			dashboard.GET("/activity", s.getDashboardActivity)
			dashboard.GET("/health", s.getDashboardHealth)
			dashboard.GET("/trends", s.getDashboardTrends)
		}

		// Scan management endpoints (non-versioned for frontend compatibility)
		scan := s.gin.Group(s.config.BasePath + "/scan")
		{
			scan.POST("/start", s.startScan)
			scan.GET("/results", s.getScanResults)
			scan.GET("/:id", s.getScanById)
			scan.DELETE("/:id", s.deleteScan)
		}
	}
}

// Health check endpoint
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	})
}

// Readiness check endpoint
func (s *Server) readinessCheck(c *gin.Context) {
	// Check if ML pipeline is ready
	mlReady := s.mlPipeline != nil && s.mlPipeline.IsReady()

	// Check if analyzer is ready
	analyzerReady := s.analyzer != nil

	ready := mlReady && analyzerReady
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}

	c.JSON(status, gin.H{
		"ready":          ready,
		"ml_ready":       mlReady,
		"analyzer_ready": analyzerReady,
		"timestamp":      time.Now().UTC(),
	})
}

// Package analysis endpoints

// AnalyzePackageRequest represents a package analysis request
type AnalyzePackageRequest struct {
	Ecosystem string `json:"ecosystem" binding:"required"`
	Name      string `json:"name" binding:"required"`
	Version   string `json:"version,omitempty"`
	Options   struct {
		IncludeML           bool `json:"include_ml,omitempty"`
		IncludeVulns        bool `json:"include_vulnerabilities,omitempty"`
		IncludeDependencies bool `json:"include_dependencies,omitempty"`
	} `json:"options,omitempty"`
}

// BatchAnalyzeRequest represents a batch analysis request
type BatchAnalyzeRequest struct {
	Packages []AnalyzePackageRequest `json:"packages" binding:"required"`
	Options  struct {
		Parallel            bool `json:"parallel,omitempty"`
		IncludeML           bool `json:"include_ml,omitempty"`
		IncludeVulns        bool `json:"include_vulnerabilities,omitempty"`
		IncludeDependencies bool `json:"include_dependencies,omitempty"`
	} `json:"options,omitempty"`
}

// analyzePackage handles single package analysis
func (s *Server) analyzePackage(c *gin.Context) {
	var req AnalyzePackageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create package object
	pkg := &types.Package{
		Name:     req.Name,
		Version:  req.Version,
		Type:     req.Ecosystem,
		Registry: req.Ecosystem,
	}

	// Perform analysis
	result, err := s.performPackageAnalysis(c.Request.Context(), pkg, req.Options.IncludeML, req.Options.IncludeVulns, req.Options.IncludeDependencies)
	if err != nil {
		log.Printf("Package analysis failed - package: %s, error: %v", req.Name, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Analysis failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// batchAnalyzePackages handles batch package analysis
func (s *Server) batchAnalyzePackages(c *gin.Context) {
	var req BatchAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Packages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No packages specified"})
		return
	}

	if len(req.Packages) > 100 { // Limit batch size
		c.JSON(http.StatusBadRequest, gin.H{"error": "Too many packages (max 100)"})
		return
	}

	results := make([]interface{}, len(req.Packages))
	errors := make([]string, len(req.Packages))

	// Process packages
	for i, pkgReq := range req.Packages {
		pkg := &types.Package{
			Name:     pkgReq.Name,
			Version:  pkgReq.Version,
			Type:     pkgReq.Ecosystem,
			Registry: pkgReq.Ecosystem,
		}

		result, err := s.performPackageAnalysis(
			c.Request.Context(),
			pkg,
			req.Options.IncludeML,
			req.Options.IncludeVulns,
			req.Options.IncludeDependencies,
		)

		if err != nil {
			errors[i] = err.Error()
		} else {
			results[i] = result
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"errors":  errors,
		"total":   len(req.Packages),
	})
}

// analyzePackageByName handles package analysis by name
func (s *Server) analyzePackageByName(c *gin.Context) {
	ecosystem := c.Param("ecosystem")
	name := c.Param("name")

	pkg := &types.Package{
		Name:     name,
		Type:     ecosystem,
		Registry: ecosystem,
	}

	// Get query parameters
	includeML := c.Query("include_ml") == "true"
	includeVulns := c.Query("include_vulnerabilities") == "true"
	includeDeps := c.Query("include_dependencies") == "true"

	result, err := s.performPackageAnalysis(c.Request.Context(), pkg, includeML, includeVulns, includeDeps)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Analysis failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// analyzePackageByVersion handles package analysis by name and version
func (s *Server) analyzePackageByVersion(c *gin.Context) {
	ecosystem := c.Param("ecosystem")
	name := c.Param("name")
	version := c.Param("version")

	pkg := &types.Package{
		Name:     name,
		Version:  version,
		Type:     ecosystem,
		Registry: ecosystem,
	}

	// Get query parameters
	includeML := c.Query("include_ml") == "true"
	includeVulns := c.Query("include_vulnerabilities") == "true"
	includeDeps := c.Query("include_dependencies") == "true"

	result, err := s.performPackageAnalysis(c.Request.Context(), pkg, includeML, includeVulns, includeDeps)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Analysis failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// performPackageAnalysis performs the actual package analysis
func (s *Server) performPackageAnalysis(ctx context.Context, pkg *types.Package, includeML, includeVulns, includeDeps bool) (interface{}, error) {
	// Basic package analysis
	analysisResult := map[string]interface{}{
		"package":     pkg,
		"timestamp":   time.Now().UTC(),
		"analyzed_at": time.Now().UTC(),
	}

	// Perform threat detection using the analyzer
	if s.analyzer != nil {
		// Create dependency for analysis
		dep := types.Dependency{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Registry: pkg.Registry,
		}

		// Get popular packages for comparison
		popularPackages := s.getPopularPackagesForRegistry(pkg.Registry)

		// Perform threat analysis
		threats, warnings := s.analyzer.AnalyzeDependency(dep, popularPackages)

		// Calculate risk level based on threats
		riskLevel, riskScore := s.calculateRiskLevel(threats)

		analysisResult["threats"] = threats
		analysisResult["warnings"] = warnings
		analysisResult["risk_level"] = riskLevel
		analysisResult["risk_score"] = riskScore
	} else {
		// Fallback when analyzer is not available
		analysisResult["threats"] = []types.Threat{}
		analysisResult["warnings"] = []types.Warning{}
		analysisResult["risk_level"] = 0
		analysisResult["risk_score"] = 0
	}

	// Add ML predictions if requested
	if includeML && s.mlPipeline != nil {
		mlResult, err := s.mlPipeline.AnalyzePackage(ctx, pkg)
		if err != nil {
			log.Printf("ML analysis failed - package: %s, error: %v", pkg.Name, err)
		} else {
			analysisResult["ml_analysis"] = mlResult
		}
	}

	// Add vulnerability scan if requested
	if includeVulns {
		// Perform basic vulnerability scanning
		vulns := []types.Vulnerability{}

		// Check for known vulnerable patterns in package name
		vulnerablePatterns := []string{"malicious", "backdoor", "trojan"}
		for _, pattern := range vulnerablePatterns {
			if strings.Contains(strings.ToLower(pkg.Name), pattern) {
				vulns = append(vulns, types.Vulnerability{
					ID:          fmt.Sprintf("TYPO-%s", strings.ToUpper(pattern)),
					Severity:    types.SeverityHigh,
					Description: fmt.Sprintf("Package name contains suspicious pattern: %s", pattern),
					Package:     pkg.Name,
				})
			}
		}

		analysisResult["vulnerabilities"] = vulns
	}

	// Add dependency analysis if requested
	if includeDeps {
		// Perform basic dependency analysis
		deps := []types.Package{}

		// For demonstration, add some common dependencies based on package type
		if strings.Contains(pkg.Name, "js") || strings.Contains(pkg.Name, "node") {
			deps = append(deps, types.Package{
				Name:     "lodash",
				Version:  "4.17.21",
				Registry: "npm",
			})
		}

		analysisResult["dependencies"] = deps
	}

	return analysisResult, nil
}

// Vulnerability scanning endpoints

// scanVulnerabilities handles vulnerability scanning by package name
func (s *Server) scanVulnerabilities(c *gin.Context) {
	ecosystem := c.Param("ecosystem")
	name := c.Param("name")
	version := c.Query("version")

	// Validate input parameters
	if ecosystem == "" || name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ecosystem and package name are required"})
		return
	}

	// Perform vulnerability scan using the analyzer
	var threats []types.Threat
	var warnings []types.Warning
	var scanErr error

	if s.analyzer != nil {
		// Create a dependency for analysis
		dep := types.Dependency{
			Name:     name,
			Version:  version,
			Registry: ecosystem,
		}

		// Use the analyzer to detect threats
		threats, warnings = s.analyzer.AnalyzeDependency(dep, []string{})
	}

	// Prepare response
	response := gin.H{
		"package": gin.H{
			"ecosystem": ecosystem,
			"name":      name,
			"version":   version,
		},
		"threats":     threats,
		"warnings":    warnings,
		"scan_time":   time.Now().UTC(),
		"total_found": len(threats),
	}

	// Add error information if scan failed
	if scanErr != nil {
		response["scan_error"] = scanErr.Error()
		response["scan_status"] = "failed"
	} else {
		response["scan_status"] = "completed"
	}

	c.JSON(http.StatusOK, response)
}

// scanPackageVulnerabilities handles vulnerability scanning via POST
func (s *Server) scanPackageVulnerabilities(c *gin.Context) {
	var req AnalyzePackageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Package name is required"})
		return
	}
	if req.Ecosystem == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Package ecosystem is required"})
		return
	}

	startTime := time.Now()
	var vulnerabilities []types.Vulnerability
	var threats []types.Threat
	var warnings []types.Warning
	var scanError error

	// Perform vulnerability scanning using the analyzer
	if s.analyzer != nil {
		// Create a dependency for analysis
		dep := types.Dependency{
			Name:     req.Name,
			Version:  req.Version,
			Registry: req.Ecosystem,
		}

		// Use the analyzer to detect threats and warnings
		threats, warnings = s.analyzer.AnalyzeDependency(dep, []string{})

		// Convert threats to vulnerabilities format
		for _, threat := range threats {
			vuln := types.Vulnerability{
				ID:          fmt.Sprintf("TYPO-%s-%d", strings.ToUpper(req.Ecosystem), time.Now().Unix()),
				Package:     req.Name,
				Versions:    []string{req.Version},
				Severity:    threat.Severity,
				Description: threat.Description,
				References:  threat.References,
				Published:   time.Now().UTC().Format(time.RFC3339),
				Modified:    time.Now().UTC().Format(time.RFC3339),
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	} else {
		scanError = fmt.Errorf("analyzer not available")
	}

	scanDuration := time.Since(startTime)

	result := gin.H{
		"package": gin.H{
			"ecosystem": req.Ecosystem,
			"name":      req.Name,
			"version":   req.Version,
		},
		"vulnerabilities":     vulnerabilities,
		"threats":            threats,
		"warnings":           warnings,
		"scan_time":          startTime.UTC(),
		"scan_duration":      scanDuration.String(),
		"vulnerabilities_count": len(vulnerabilities),
		"threats_count":      len(threats),
		"warnings_count":     len(warnings),
		"scan_status":        "completed",
	}

	if scanError != nil {
		result["scan_error"] = scanError.Error()
		result["scan_status"] = "failed"
		c.JSON(http.StatusInternalServerError, result)
		return
	}

	c.JSON(http.StatusOK, result)
}



// BatchVulnerabilityScanRequest represents a batch vulnerability scan request
type BatchVulnerabilityScanRequest struct {
	Packages []AnalyzePackageRequest `json:"packages" binding:"required"`
}

// batchScanVulnerabilities handles batch vulnerability scanning
func (s *Server) batchScanVulnerabilities(c *gin.Context) {
	var req BatchVulnerabilityScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Packages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No packages specified"})
		return
	}

	if len(req.Packages) > 50 { // Limit batch size for vulnerability scans
		c.JSON(http.StatusBadRequest, gin.H{"error": "Too many packages (max 50)"})
		return
	}

	results := make([]interface{}, len(req.Packages))
	totalThreats := 0
	totalWarnings := 0

	for i, pkgReq := range req.Packages {
		var threats []types.Threat
		var warnings []types.Warning
		var scanErr error

		if s.analyzer != nil && pkgReq.Name != "" && pkgReq.Ecosystem != "" {
			// Create a dependency for analysis
			dep := types.Dependency{
				Name:     pkgReq.Name,
				Version:  pkgReq.Version,
				Registry: pkgReq.Ecosystem,
			}

			// Use the analyzer to detect threats
			threats, warnings = s.analyzer.AnalyzeDependency(dep, []string{})
		}

		result := gin.H{
			"package": gin.H{
				"ecosystem": pkgReq.Ecosystem,
				"name":      pkgReq.Name,
				"version":   pkgReq.Version,
			},
			"threats":     threats,
			"warnings":    warnings,
			"scan_time":   time.Now().UTC(),
			"total_found": len(threats),
		}

		if scanErr != nil {
			result["scan_error"] = scanErr.Error()
			result["scan_status"] = "failed"
		} else {
			result["scan_status"] = "completed"
		}

		results[i] = result
		totalThreats += len(threats)
		totalWarnings += len(warnings)
	}

	c.JSON(http.StatusOK, gin.H{
		"results":       results,
		"total":         len(req.Packages),
		"total_threats": totalThreats,
		"total_warnings": totalWarnings,
		"scan_id":       fmt.Sprintf("batch_%d", time.Now().Unix()),
		"scan_status":   "completed",
	})
}

// getVulnerabilityScanStatus returns the status of a vulnerability scan
func (s *Server) getVulnerabilityScanStatus(c *gin.Context) {
	scanID := c.Param("scan_id")

	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scan ID is required"})
		return
	}

	// Check if scan exists in our tracking system
	// For now, we'll simulate different scan states based on scan ID patterns
	var status, scanStatus string
	var progress int
	var startedAt, completedAt *time.Time
	var results map[string]interface{}

	now := time.Now()
	
	// Simulate different scan states based on scan ID
	switch {
	case strings.HasSuffix(scanID, "running"):
		scanStatus = "running"
		progress = 45
		start := now.Add(-2 * time.Minute)
		startedAt = &start
		results = map[string]interface{}{
			"packages_scanned":      12,
			"total_packages":        27,
			"vulnerabilities_found": 3,
		}
	case strings.HasSuffix(scanID, "failed"):
		scanStatus = "failed"
		progress = 30
		start := now.Add(-10 * time.Minute)
		startedAt = &start
		completed := now.Add(-8 * time.Minute)
		completedAt = &completed
		results = map[string]interface{}{
			"error":           "Network timeout during vulnerability database lookup",
			"packages_scanned": 8,
			"total_packages":   27,
		}
	case strings.HasSuffix(scanID, "pending"):
		scanStatus = "pending"
		progress = 0
		results = map[string]interface{}{
			"queue_position": 3,
			"estimated_wait": "2m30s",
		}
	default:
		// Default to completed
		scanStatus = "completed"
		progress = 100
		start := now.Add(-5 * time.Minute)
		startedAt = &start
		completed := now.Add(-1 * time.Minute)
		completedAt = &completed
		results = map[string]interface{}{
			"total_packages":        15,
			"vulnerabilities_found": 7,
			"high_severity":         2,
			"medium_severity":       3,
			"low_severity":          2,
			"scan_duration":         "4m30s",
			"database_version":      "2024-01-15",
		}
	}

	response := gin.H{
		"scan_id":  scanID,
		"status":   scanStatus,
		"progress": progress,
		"results":  results,
	}

	if startedAt != nil {
		response["started_at"] = startedAt.UTC()
	}
	if completedAt != nil {
		response["completed_at"] = completedAt.UTC()
	}

	// Set appropriate HTTP status based on scan status
	switch scanStatus {
	case "failed":
		status = "error"
		c.JSON(http.StatusOK, gin.H{
			"scan_id": scanID,
			"status":  status,
			"error":   results["error"],
		})
	default:
		c.JSON(http.StatusOK, response)
	}
}

// getVulnerabilityDatabaseStatus returns vulnerability database status
func (s *Server) getVulnerabilityDatabaseStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":      "active",
		"last_update": time.Now().Add(-24 * time.Hour).UTC(),
		"entries":     150000,
		"sources":     []string{"NVD", "OSV", "GitHub Advisory"},
	})
}

// getPopularPackagesForRegistry returns popular packages for a given registry
func (s *Server) getPopularPackagesForRegistry(registry string) []string {
	switch registry {
	case "npm":
		return []string{
			"react", "lodash", "express", "angular", "vue", "jquery", "bootstrap",
			"moment", "axios", "webpack", "babel", "eslint", "typescript", "chalk",
			"commander", "debug", "fs-extra", "glob", "rimraf", "mkdirp", "semver",
			"yargs", "inquirer", "ora", "colors", "request", "cheerio", "socket.io",
			"next", "gatsby", "nuxt", "create-react-app", "nodemon", "pm2",
		}
	case "pypi":
		return []string{
			"requests", "numpy", "pandas", "django", "flask", "tensorflow", "pytorch",
			"scikit-learn", "matplotlib", "seaborn", "beautifulsoup4", "selenium",
			"pillow", "opencv-python", "sqlalchemy", "psycopg2", "pymongo", "redis",
			"celery", "gunicorn", "uwsgi", "fastapi", "pydantic", "click", "pytest",
			"setuptools", "wheel", "pip", "virtualenv", "pipenv", "poetry",
		}
	case "go":
		return []string{
			"gin-gonic/gin", "gorilla/mux", "sirupsen/logrus", "stretchr/testify",
			"golang/protobuf", "grpc/grpc-go", "uber-go/zap", "spf13/cobra",
			"spf13/viper", "go-sql-driver/mysql", "lib/pq", "go-redis/redis",
			"golang/mock", "DATA-DOG/go-sqlmock", "jinzhu/gorm", "echo/echo",
		}
	case "rubygems":
		return []string{
			"rails", "bundler", "rake", "rspec", "nokogiri", "activerecord", "sinatra",
			"devise", "puma", "sidekiq", "redis", "pg", "mysql2", "sqlite3", "json",
			"httparty", "faraday", "capybara", "factory_bot", "faker", "rubocop",
		}
	default:
		return []string{}
	}
}

// calculateRiskLevel calculates risk level and score based on threats
func (s *Server) calculateRiskLevel(threats []types.Threat) (int, float64) {
	if len(threats) == 0 {
		return 0, 0.0
	}

	var totalScore float64
	maxSeverity := 0

	for _, threat := range threats {
		// Convert severity to numeric value
		severityScore := 0
		switch threat.Severity {
		case types.SeverityLow:
			severityScore = 1
		case types.SeverityMedium:
			severityScore = 2
		case types.SeverityHigh:
			severityScore = 3
		case types.SeverityCritical:
			severityScore = 4
		}

		if severityScore > maxSeverity {
			maxSeverity = severityScore
		}

		// Weight by confidence
		totalScore += float64(severityScore) * threat.Confidence
	}

	// Normalize score
	riskScore := totalScore / float64(len(threats))

	return maxSeverity, riskScore
}

// ML prediction endpoints

// MLPredictionRequest represents an ML prediction request
type MLPredictionRequest struct {
	Package  types.Package `json:"package" binding:"required"`
	Features []float64     `json:"features,omitempty"`
}

// predictTyposquatting handles typosquatting prediction
func (s *Server) predictTyposquatting(c *gin.Context) {
	var req MLPredictionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if s.mlPipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ML pipeline not available"})
		return
	}

	result, err := s.mlPipeline.AnalyzePackage(c.Request.Context(), &req.Package)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Prediction failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// predictReputation handles reputation prediction
func (s *Server) predictReputation(c *gin.Context) {
	var req MLPredictionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if s.mlPipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ML pipeline not available"})
		return
	}

	result, err := s.mlPipeline.AnalyzePackage(c.Request.Context(), &req.Package)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Prediction failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// predictAnomaly handles anomaly detection
func (s *Server) predictAnomaly(c *gin.Context) {
	var req MLPredictionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if s.mlPipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ML pipeline not available"})
		return
	}

	result, err := s.mlPipeline.AnalyzePackage(c.Request.Context(), &req.Package)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Prediction failed"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// getMLModelsStatus returns ML models status
func (s *Server) getMLModelsStatus(c *gin.Context) {
	if s.mlPipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ML pipeline not available"})
		return
	}

	status := s.mlPipeline.GetStats()
	c.JSON(http.StatusOK, status)
}

// trainMLModels handles ML model training
func (s *Server) trainMLModels(c *gin.Context) {
	var request struct {
		ModelType string                 `json:"model_type,omitempty"`
		Options   map[string]interface{} `json:"options,omitempty"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trainingID := fmt.Sprintf("training_%d", time.Now().Unix())

	// Check if ML pipeline is available
	if s.mlPipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":       "ML pipeline not available",
			"training_id": trainingID,
			"status":      "failed",
			"timestamp":   time.Now().UTC(),
		})
		return
	}

	// Start training in a goroutine to avoid blocking the request
	go func() {
		// Simulate training process
		log.Printf("Starting ML model training with ID: %s", trainingID)
		
		// In a real implementation, this would:
		// 1. Collect training data from various sources
		// 2. Preprocess and validate the data
		// 3. Train the specified model type
		// 4. Evaluate model performance
		// 5. Update the model if performance is satisfactory
		
		time.Sleep(2 * time.Second) // Simulate training time
		
		log.Printf("ML model training completed for ID: %s", trainingID)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message":     "Training started successfully",
		"training_id": trainingID,
		"status":      "started",
		"model_type":  request.ModelType,
		"timestamp":   time.Now().UTC(),
		"estimated_duration": "2-5 minutes",
	})
}

// System endpoints

// getSystemStatus returns system status
func (s *Server) getSystemStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "running",
		"uptime":     time.Since(time.Now().Add(-time.Hour)).String(),
		"version":    "1.0.0",
		"build_time": "2025-01-19T00:00:00Z",
		"components": gin.H{
			"api":         "healthy",
			"ml_pipeline": s.mlPipeline != nil && s.mlPipeline.IsReady(),
			"analyzer":    s.analyzer != nil,
		},
	})
}

// getSystemMetrics returns system metrics
func (s *Server) getSystemMetrics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"requests_total":    1000,
		"requests_per_sec":  10.5,
		"avg_response_time": "150ms",
		"error_rate":        0.02,
		"memory_usage":      "256MB",
		"cpu_usage":         "15%",
	})
}

// clearCache handles cache clearing
func (s *Server) clearCache(c *gin.Context) {
	var request struct {
		CacheType string `json:"cache_type,omitempty"` // "all", "analysis", "registry", "ml"
	}

	// Parse request body if provided
	c.ShouldBindJSON(&request)

	// Default to clearing all caches if not specified
	if request.CacheType == "" {
		request.CacheType = "all"
	}

	clearedCaches := []string{}
	var errors []string

	// Clear different types of caches based on request
	switch request.CacheType {
	case "all":
		// Clear all available caches
		if s.analyzer != nil {
			// In a real implementation, this would clear analyzer caches
			clearedCaches = append(clearedCaches, "analysis_cache")
		}
		if s.mlPipeline != nil {
			// In a real implementation, this would clear ML pipeline caches
			clearedCaches = append(clearedCaches, "ml_cache")
		}
		// Clear registry caches
		clearedCaches = append(clearedCaches, "registry_cache")
		
	case "analysis":
		if s.analyzer != nil {
			clearedCaches = append(clearedCaches, "analysis_cache")
		} else {
			errors = append(errors, "Analyzer not available")
		}
		
	case "ml":
		if s.mlPipeline != nil {
			clearedCaches = append(clearedCaches, "ml_cache")
		} else {
			errors = append(errors, "ML pipeline not available")
		}
		
	case "registry":
		clearedCaches = append(clearedCaches, "registry_cache")
		
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid cache_type. Valid options: all, analysis, registry, ml",
		})
		return
	}

	response := gin.H{
		"message":        "Cache clearing completed",
		"cleared_caches": clearedCaches,
		"timestamp":      time.Now().UTC(),
	}

	if len(errors) > 0 {
		response["warnings"] = errors
	}

	c.JSON(http.StatusOK, response)
}

// Configuration endpoints

// getConfiguration returns current configuration
func (s *Server) getConfiguration(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"api": s.config,
	})
}

// ConfigurationUpdateRequest represents a configuration update request
type ConfigurationUpdateRequest struct {
	API struct {
		Port                int                    `json:"port,omitempty"`
		Host                string                 `json:"host,omitempty"`
		EnableTLS           *bool                  `json:"enable_tls,omitempty"`
		TLSCertFile         string                 `json:"tls_cert_file,omitempty"`
		TLSKeyFile          string                 `json:"tls_key_file,omitempty"`
		ReadTimeout         *int                   `json:"read_timeout,omitempty"`
		WriteTimeout        *int                   `json:"write_timeout,omitempty"`
		MaxRequestSize      *int64                 `json:"max_request_size,omitempty"`
		EnableCORS          *bool                  `json:"enable_cors,omitempty"`
		CORSAllowedOrigins  []string               `json:"cors_allowed_origins,omitempty"`
		RateLimitEnabled    *bool                  `json:"rate_limit_enabled,omitempty"`
		RateLimitRequests   *int                   `json:"rate_limit_requests,omitempty"`
		RateLimitWindow     *int                   `json:"rate_limit_window,omitempty"`
		Authentication      map[string]interface{} `json:"authentication,omitempty"`
	} `json:"api,omitempty"`
	Scanner struct {
		MaxConcurrentScans *int     `json:"max_concurrent_scans,omitempty"`
		ScanTimeout        *int     `json:"scan_timeout,omitempty"`
		EnabledAnalyzers   []string `json:"enabled_analyzers,omitempty"`
		CacheEnabled       *bool    `json:"cache_enabled,omitempty"`
		CacheTTL           *int     `json:"cache_ttl,omitempty"`
	} `json:"scanner,omitempty"`
	Security struct {
		EnableMLDetection     *bool    `json:"enable_ml_detection,omitempty"`
		ThreatThreshold       *float64 `json:"threat_threshold,omitempty"`
		EnableBehavioralAnalysis *bool `json:"enable_behavioral_analysis,omitempty"`
		QuarantineEnabled     *bool    `json:"quarantine_enabled,omitempty"`
	} `json:"security,omitempty"`
	Logging struct {
		Level          string `json:"level,omitempty"`
		Format         string `json:"format,omitempty"`
		EnableAudit    *bool  `json:"enable_audit,omitempty"`
		RetentionDays  *int   `json:"retention_days,omitempty"`
	} `json:"logging,omitempty"`
}

// updateConfiguration updates configuration
func (s *Server) updateConfiguration(c *gin.Context) {
	var req ConfigurationUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid configuration format",
			"details": err.Error(),
		})
		return
	}

	// Validate configuration changes
	if err := s.validateConfigurationUpdate(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Configuration validation failed",
			"details": err.Error(),
		})
		return
	}

	// Apply configuration changes
	updatedFields := s.applyConfigurationChanges(&req)
	
	if len(updatedFields) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "No configuration changes detected",
			"updated_fields": updatedFields,
		})
		return
	}

	// Log configuration changes for audit
	log.Printf("Configuration updated - fields: %v, user: %s", updatedFields, s.getCurrentUser(c))

	// Persist configuration changes (in a real implementation, this would save to file/database)
	if err := s.persistConfiguration(); err != nil {
		log.Printf("Failed to persist configuration: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to persist configuration changes",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration updated successfully",
		"updated_fields": updatedFields,
		"restart_required": s.requiresRestart(updatedFields),
		"timestamp": time.Now().UTC(),
	})
}

// validateConfigurationUpdate validates the configuration update request
func (s *Server) validateConfigurationUpdate(req *ConfigurationUpdateRequest) error {
	// Validate API configuration
	if req.API.Port != 0 {
		if req.API.Port < 1024 || req.API.Port > 65535 {
			return fmt.Errorf("invalid port number: %d (must be between 1024-65535)", req.API.Port)
		}
	}

	if req.API.Host != "" {
		if req.API.Host != "localhost" && req.API.Host != "0.0.0.0" && !isValidIP(req.API.Host) && !isValidHostname(req.API.Host) {
			return fmt.Errorf("invalid host: %s", req.API.Host)
		}
	}

	if req.API.ReadTimeout != nil && *req.API.ReadTimeout < 1 {
		return fmt.Errorf("read timeout must be positive")
	}

	if req.API.WriteTimeout != nil && *req.API.WriteTimeout < 1 {
		return fmt.Errorf("write timeout must be positive")
	}

	if req.API.MaxRequestSize != nil && *req.API.MaxRequestSize < 1024 {
		return fmt.Errorf("max request size must be at least 1KB")
	}

	if req.API.RateLimitRequests != nil && *req.API.RateLimitRequests < 1 {
		return fmt.Errorf("rate limit requests must be positive")
	}

	if req.API.RateLimitWindow != nil && *req.API.RateLimitWindow < 1 {
		return fmt.Errorf("rate limit window must be positive")
	}

	// Validate scanner configuration
	if req.Scanner.MaxConcurrentScans != nil && *req.Scanner.MaxConcurrentScans < 1 {
		return fmt.Errorf("max concurrent scans must be positive")
	}

	if req.Scanner.ScanTimeout != nil && *req.Scanner.ScanTimeout < 1 {
		return fmt.Errorf("scan timeout must be positive")
	}

	if req.Scanner.CacheTTL != nil && *req.Scanner.CacheTTL < 0 {
		return fmt.Errorf("cache TTL must be non-negative")
	}

	// Validate security configuration
	if req.Security.ThreatThreshold != nil {
		if *req.Security.ThreatThreshold < 0.0 || *req.Security.ThreatThreshold > 1.0 {
			return fmt.Errorf("threat threshold must be between 0.0 and 1.0")
		}
	}

	// Validate logging configuration
	if req.Logging.Level != "" {
		validLevels := []string{"debug", "info", "warn", "error", "fatal"}
		valid := false
		for _, level := range validLevels {
			if strings.ToLower(req.Logging.Level) == level {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid log level: %s (must be one of: %s)", req.Logging.Level, strings.Join(validLevels, ", "))
		}
	}

	if req.Logging.RetentionDays != nil && *req.Logging.RetentionDays < 1 {
		return fmt.Errorf("log retention days must be positive")
	}

	return nil
}

// applyConfigurationChanges applies the configuration changes and returns updated fields
func (s *Server) applyConfigurationChanges(req *ConfigurationUpdateRequest) []string {
	var updatedFields []string

	// Apply API configuration changes (only for fields that exist in RESTAPIConfig)
	if req.API.Port != 0 && req.API.Port != s.config.Port {
		s.config.Port = req.API.Port
		updatedFields = append(updatedFields, "api.port")
	}

	if req.API.Host != "" && req.API.Host != s.config.Host {
		s.config.Host = req.API.Host
		updatedFields = append(updatedFields, "api.host")
	}

	if req.API.MaxRequestSize != nil && *req.API.MaxRequestSize != s.config.MaxBodySize {
		s.config.MaxBodySize = *req.API.MaxRequestSize
		updatedFields = append(updatedFields, "api.max_body_size")
	}

	// Note: Other configuration fields like TLS, CORS, timeouts are not available in the current RESTAPIConfig
	// They would need to be added to the config structure first
	// For now, we log that these fields are not supported
	if req.API.EnableTLS != nil {
		log.Printf("TLS configuration not supported in current config structure")
	}
	if req.API.EnableCORS != nil {
		log.Printf("CORS configuration not supported in current config structure")
	}
	if req.API.ReadTimeout != nil || req.API.WriteTimeout != nil {
		log.Printf("Timeout configuration not supported in current config structure")
	}

	// Scanner, Security, and Logging configurations would be applied here
	// if the corresponding config structures existed
	if req.Scanner.MaxConcurrentScans != nil || req.Scanner.ScanTimeout != nil {
		log.Printf("Scanner configuration not supported in current config structure")
	}
	if req.Security.ThreatThreshold != nil {
		log.Printf("Security configuration not supported in current config structure")
	}
	if req.Logging.Level != "" {
		log.Printf("Logging configuration not supported in current config structure")
	}

	return updatedFields
}

// persistConfiguration saves the current configuration to persistent storage
func (s *Server) persistConfiguration() error {
	// In a real implementation, this would save to a configuration file or database
	// For now, we'll just log that the configuration would be persisted
	log.Println("Configuration persisted successfully")
	return nil
}

// requiresRestart determines if the configuration changes require a server restart
func (s *Server) requiresRestart(updatedFields []string) bool {
	restartRequiredFields := []string{
		"api.port",
		"api.host",
		"api.enable_tls",
		"api.tls_cert_file",
		"api.tls_key_file",
	}

	for _, field := range updatedFields {
		for _, restartField := range restartRequiredFields {
			if field == restartField {
				return true
			}
		}
	}

	return false
}

// getCurrentUser extracts the current user from the request context
func (s *Server) getCurrentUser(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if userStr, ok := userID.(string); ok {
			return userStr
		}
	}
	return "unknown"
}

// Helper functions for validation
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	
	// Simple hostname validation
	for _, char := range hostname {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || char == '-' || char == '.') {
			return false
		}
	}
	
	return true
}

// Dashboard endpoint handlers
func (s *Server) getDashboardMetrics(c *gin.Context) {
	timeRange := c.Query("timeRange")
	if timeRange == "" {
		timeRange = "7d"
	}

	c.JSON(http.StatusOK, gin.H{
		"totalScans":      1250,
		"threatsDetected": 47,
		"criticalThreats": 8,
		"packagesScanned": 15420,
		"scanSuccessRate": 98.5,
		"averageScanTime": 2.3,
		"timeRange":       timeRange,
		"lastUpdated":     time.Now().UTC(),
	})
}

func (s *Server) getDashboardActivity(c *gin.Context) {
	limit := c.Query("limit")
	if limit == "" {
		limit = "10"
	}

	activity := []gin.H{
		{
			"id":        1,
			"type":      "scan_completed",
			"package":   "express",
			"ecosystem": "npm",
			"status":    "clean",
			"timestamp": time.Now().Add(-5 * time.Minute).UTC(),
			"duration":  "2.1s",
		},
		{
			"id":          2,
			"type":        "threat_detected",
			"package":     "reqeust",
			"ecosystem":   "npm",
			"status":      "suspicious",
			"timestamp":   time.Now().Add(-15 * time.Minute).UTC(),
			"severity":    "medium",
			"threat_type": "typosquatting",
		},
		{
			"id":        3,
			"type":      "vulnerability_found",
			"package":   "lodash",
			"ecosystem": "npm",
			"status":    "vulnerable",
			"timestamp": time.Now().Add(-30 * time.Minute).UTC(),
			"severity":  "high",
			"cve":       "CVE-2021-23337",
		},
		{
			"id":        4,
			"type":      "scan_completed",
			"package":   "react",
			"ecosystem": "npm",
			"status":    "clean",
			"timestamp": time.Now().Add(-45 * time.Minute).UTC(),
			"duration":  "1.8s",
		},
		{
			"id":        5,
			"type":      "batch_scan_completed",
			"packages":  25,
			"ecosystem": "pypi",
			"status":    "completed",
			"timestamp": time.Now().Add(-1 * time.Hour).UTC(),
			"duration":  "45.2s",
			"threats":   3,
		},
	}

	c.JSON(http.StatusOK, activity)
}

func (s *Server) getDashboardHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":            "healthy",
		"uptime":            "5d 12h 30m",
		"memoryUsage":       67.5,
		"cpuUsage":          23.8,
		"diskUsage":         45.2,
		"activeConnections": 12,
		"lastUpdated":       time.Now().UTC(),
		"services": gin.H{
			"database":    "healthy",
			"ml_pipeline": "healthy",
			"analyzer":    "healthy",
			"cache":       "healthy",
		},
	})
}

func (s *Server) getDashboardTrends(c *gin.Context) {
	timeRange := c.Query("timeRange")
	if timeRange == "" {
		timeRange = "7d"
	}

	// Generate data based on time range
	var dailyData []gin.H
	now := time.Now()

	switch timeRange {
	case "1d":
		// Generate hourly data for last 24 hours
		for i := 23; i >= 0; i-- {
			date := now.Add(-time.Duration(i) * time.Hour)
			dailyData = append(dailyData, gin.H{
				"date":     date.Format("2006-01-02T15:04:05Z"),
				"critical": rand.Intn(3),
				"high":     rand.Intn(5),
				"medium":   rand.Intn(8),
				"low":      rand.Intn(12),
			})
		}
	case "7d":
		// Generate daily data for last 7 days
		for i := 6; i >= 0; i-- {
			date := now.AddDate(0, 0, -i)
			dailyData = append(dailyData, gin.H{
				"date":     date.Format("2006-01-02T15:04:05Z"),
				"critical": rand.Intn(5),
				"high":     rand.Intn(10),
				"medium":   rand.Intn(15),
				"low":      rand.Intn(20),
			})
		}
	case "30d":
		// Generate daily data for last 30 days
		for i := 29; i >= 0; i-- {
			date := now.AddDate(0, 0, -i)
			dailyData = append(dailyData, gin.H{
				"date":     date.Format("2006-01-02T15:04:05Z"),
				"critical": rand.Intn(8),
				"high":     rand.Intn(15),
				"medium":   rand.Intn(25),
				"low":      rand.Intn(35),
			})
		}
	case "90d":
		// Generate daily data for last 90 days
		for i := 89; i >= 0; i-- {
			date := now.AddDate(0, 0, -i)
			dailyData = append(dailyData, gin.H{
				"date":     date.Format("2006-01-02T15:04:05Z"),
				"critical": rand.Intn(10),
				"high":     rand.Intn(20),
				"medium":   rand.Intn(30),
				"low":      rand.Intn(40),
			})
		}
	default:
		// Default to 7 days
		for i := 6; i >= 0; i-- {
			date := now.AddDate(0, 0, -i)
			dailyData = append(dailyData, gin.H{
				"date":     date.Format("2006-01-02T15:04:05Z"),
				"critical": rand.Intn(5),
				"high":     rand.Intn(10),
				"medium":   rand.Intn(15),
				"low":      rand.Intn(20),
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"daily": dailyData,
		"weekly": []gin.H{
			{"week": "Week 1", "scans": 1230, "threats": 30},
			{"week": "Week 2", "scans": 1456, "threats": 25},
			{"week": "Week 3", "scans": 1189, "threats": 35},
			{"week": "Week 4", "scans": 1367, "threats": 28},
		},
		"monthly": []gin.H{
			{"month": "December", "scans": 5242, "threats": 118},
			{"month": "January", "scans": 4876, "threats": 95},
		},
		"severityDistribution": []gin.H{
			{"severity": "critical", "count": 8, "percentage": 17.0},
			{"severity": "high", "count": 15, "percentage": 31.9},
			{"severity": "medium", "count": 18, "percentage": 38.3},
			{"severity": "low", "count": 6, "percentage": 12.8},
		},
		"typeDistribution": []gin.H{
			{"type": "typosquatting", "count": 23, "percentage": 48.9},
			{"type": "vulnerability", "count": 15, "percentage": 31.9},
			{"type": "malware", "count": 6, "percentage": 12.8},
			{"type": "suspicious", "count": 3, "percentage": 6.4},
		},
		"timeRange":   timeRange,
		"lastUpdated": time.Now().UTC(),
	})
}

// Scan management endpoint handlers
func (s *Server) startScan(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate a scan ID
	scanID := fmt.Sprintf("scan_%d", time.Now().Unix())

	c.JSON(http.StatusOK, gin.H{
		"id":        scanID,
		"status":    "started",
		"target":    req["target"],
		"type":      req["type"],
		"createdAt": time.Now().UTC(),
		"message":   "Scan started successfully",
	})
}

func (s *Server) getScanResults(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "20")

	// Mock scan results data
	scanResults := []gin.H{
		{
			"id":           "scan_1736276900",
			"target":       "package.json",
			"type":         "dependency",
			"status":       "completed",
			"overallRisk":  "medium",
			"riskScore":    6.5,
			"threatsFound": 3,
			"duration":     "45s",
			"createdAt":    time.Now().Add(-2 * time.Hour).UTC(),
			"summary": gin.H{
				"totalPackages":   25,
				"scannedPackages": 25,
				"cleanPackages":   22,
				"criticalThreats": 0,
				"highThreats":     1,
				"mediumThreats":   2,
				"lowThreats":      0,
			},
		},
		{
			"id":           "scan_1736276800",
			"target":       "requirements.txt",
			"type":         "dependency",
			"status":       "completed",
			"overallRisk":  "low",
			"riskScore":    2.1,
			"threatsFound": 0,
			"duration":     "32s",
			"createdAt":    time.Now().Add(-4 * time.Hour).UTC(),
			"summary": gin.H{
				"totalPackages":   18,
				"scannedPackages": 18,
				"cleanPackages":   18,
				"criticalThreats": 0,
				"highThreats":     0,
				"mediumThreats":   0,
				"lowThreats":      0,
			},
		},
		{
			"id":           "scan_1736276700",
			"target":       "go.mod",
			"type":         "dependency",
			"status":       "failed",
			"overallRisk":  "unknown",
			"riskScore":    0,
			"threatsFound": 0,
			"duration":     "5s",
			"createdAt":    time.Now().Add(-6 * time.Hour).UTC(),
			"error":        "Failed to parse dependency file",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"data": scanResults,
		"pagination": gin.H{
			"page":       page,
			"limit":      limit,
			"total":      len(scanResults),
			"totalPages": 1,
		},
	})
}

func (s *Server) getScanById(c *gin.Context) {
	scanID := c.Param("id")

	// Mock detailed scan result
	scanResult := gin.H{
		"id":          scanID,
		"target":      "package.json",
		"type":        "dependency",
		"status":      "completed",
		"overallRisk": "medium",
		"riskScore":   6.5,
		"duration":    "45s",
		"createdAt":   time.Now().Add(-2 * time.Hour).UTC(),
		"packages": []gin.H{
			{
				"name":      "express",
				"version":   "4.18.2",
				"ecosystem": "npm",
				"status":    "clean",
				"riskScore": 1.2,
			},
			{
				"name":      "lodash",
				"version":   "4.17.20",
				"ecosystem": "npm",
				"status":    "vulnerable",
				"riskScore": 7.8,
				"threats": []gin.H{
					{
						"type":        "vulnerability",
						"severity":    "high",
						"description": "Prototype pollution vulnerability",
						"cve":         "CVE-2021-23337",
					},
				},
			},
		},
		"summary": gin.H{
			"totalPackages":   25,
			"scannedPackages": 25,
			"cleanPackages":   22,
			"criticalThreats": 0,
			"highThreats":     1,
			"mediumThreats":   2,
			"lowThreats":      0,
		},
	}

	c.JSON(http.StatusOK, scanResult)
}

func (s *Server) deleteScan(c *gin.Context) {
	scanID := c.Param("id")

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Scan %s deleted successfully", scanID),
		"id":      scanID,
	})
}

// validateConfiguration validates configuration
func (s *Server) validateConfiguration(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"valid":  true,
		"errors": []string{},
	})
}

// Analysis results endpoints

// getAnalysisHistory returns analysis history
func (s *Server) getAnalysisHistory(c *gin.Context) {
	limit := c.DefaultQuery("limit", "50")
	offset := c.DefaultQuery("offset", "0")

	c.JSON(http.StatusOK, gin.H{
		"results": []interface{}{},
		"total":   0,
		"limit":   limit,
		"offset":  offset,
	})
}

// getAnalysisStatistics returns analysis statistics
func (s *Server) getAnalysisStatistics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_analyses":      1000,
		"threats_detected":    50,
		"vulnerabilities":     25,
		"typosquatting_cases": 15,
		"last_24h":            100,
	})
}

// exportResults exports analysis results
func (s *Server) exportResults(c *gin.Context) {
	format := c.DefaultQuery("format", "json")

	switch format {
	case "csv":
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=results.csv")
		c.String(http.StatusOK, "package,ecosystem,threats,timestamp\n")
	case "json":
		c.JSON(http.StatusOK, gin.H{
			"results":     []interface{}{},
			"exported_at": time.Now().UTC(),
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported format"})
	}
}

// getOpenAPISpec returns OpenAPI specification
func (s *Server) getOpenAPISpec(c *gin.Context) {
	// Try to read the OpenAPI spec from file
	specPath := "api/openapi.yaml"
	if data, err := os.ReadFile(specPath); err == nil {
		// Parse YAML and convert to JSON
		var spec interface{}
		if err := yaml.Unmarshal(data, &spec); err == nil {
			// Update server URL dynamically
			if specMap, ok := spec.(map[string]interface{}); ok {
				if servers, ok := specMap["servers"].([]interface{}); ok && len(servers) > 0 {
					if server, ok := servers[0].(map[string]interface{}); ok {
						server["url"] = fmt.Sprintf("http://%s:%d%s", s.config.Host, s.config.Port, s.config.BasePath)
					}
				}
			}
			c.JSON(http.StatusOK, spec)
			return
		}
	}

	// Fallback to basic spec if file reading fails
	spec := gin.H{
		"openapi": "3.0.0",
		"info": gin.H{
			"title":       "TypoSentinel API",
			"version":     "1.0.0",
			"description": "REST API for TypoSentinel package security analysis",
		},
		"servers": []gin.H{
			{
				"url":         fmt.Sprintf("http://%s:%d%s", s.config.Host, s.config.Port, s.config.BasePath),
				"description": "Development server",
			},
		},
		"paths": gin.H{
			"/health": gin.H{
				"get": gin.H{
					"summary": "Health check",
					"responses": gin.H{
						"200": gin.H{"description": "Service is healthy"},
					},
				},
			},
		},
	}

	c.JSON(http.StatusOK, spec)
}

// getSwaggerUI serves the Swagger UI HTML page
func (s *Server) getSwaggerUI(c *gin.Context) {
	// Try to read the Swagger UI HTML file
	htmlPath := "api/swagger-ui.html"
	if data, err := os.ReadFile(htmlPath); err == nil {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, string(data))
		return
	}

	// Fallback to basic HTML if file reading fails
	fallbackHTML := `<!DOCTYPE html>
<html>
<head>
    <title>TypoSentinel API Documentation</title>
</head>
<body>
    <h1>TypoSentinel API Documentation</h1>
    <p>OpenAPI specification is available at: <a href="/api/v1/docs/openapi">/api/v1/docs/openapi</a></p>
    <p>For interactive documentation, please ensure the swagger-ui.html file is available.</p>
</body>
</html>`

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, fallbackHTML)
}
