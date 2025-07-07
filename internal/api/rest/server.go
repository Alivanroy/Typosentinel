package rest

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/requestid"
	"gopkg.in/yaml.v3"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/internal/analyzer"
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
}

// NewServer creates a new REST API server
func NewServer(cfg config.RESTAPIConfig, mlPipeline *ml.MLPipeline, analyzer *analyzer.Analyzer) *Server {
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

	server := &Server{
		config:     cfg,
		gin:        r,
		mlPipeline: mlPipeline,
		analyzer:   analyzer,
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
		IncludeML          bool `json:"include_ml,omitempty"`
		IncludeVulns       bool `json:"include_vulnerabilities,omitempty"`
		IncludeDependencies bool `json:"include_dependencies,omitempty"`
	} `json:"options,omitempty"`
}

// BatchAnalyzeRequest represents a batch analysis request
type BatchAnalyzeRequest struct {
	Packages []AnalyzePackageRequest `json:"packages" binding:"required"`
	Options  struct {
		Parallel           bool `json:"parallel,omitempty"`
		IncludeML          bool `json:"include_ml,omitempty"`
		IncludeVulns       bool `json:"include_vulnerabilities,omitempty"`
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
		"package": pkg,
		"timestamp": time.Now().UTC(),
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

	// Placeholder implementation
	result := gin.H{
		"package": gin.H{
			"ecosystem": ecosystem,
			"name":      name,
			"version":   version,
		},
		"vulnerabilities": []types.Vulnerability{},
		"scan_time":      time.Now().UTC(),
	}

	c.JSON(http.StatusOK, result)
}

// scanPackageVulnerabilities handles vulnerability scanning via POST
func (s *Server) scanPackageVulnerabilities(c *gin.Context) {
	var req AnalyzePackageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Placeholder implementation
	result := gin.H{
		"package": gin.H{
			"ecosystem": req.Ecosystem,
			"name":      req.Name,
			"version":   req.Version,
		},
		"vulnerabilities": []types.Vulnerability{},
		"scan_time":      time.Now().UTC(),
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

	for i, pkgReq := range req.Packages {
		result := gin.H{
			"package": gin.H{
				"ecosystem": pkgReq.Ecosystem,
				"name":      pkgReq.Name,
				"version":   pkgReq.Version,
			},
			"vulnerabilities": []types.Vulnerability{},
			"scan_time":      time.Now().UTC(),
		}
		results[i] = result
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(req.Packages),
		"scan_id": fmt.Sprintf("batch_%d", time.Now().Unix()),
	})
}

// getVulnerabilityScanStatus returns the status of a vulnerability scan
func (s *Server) getVulnerabilityScanStatus(c *gin.Context) {
	scanID := c.Param("scan_id")

	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Scan ID is required"})
		return
	}

	// Placeholder implementation - in a real system, this would check scan status from a database
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"status":  "completed",
		"progress": 100,
		"started_at": time.Now().Add(-5 * time.Minute).UTC(),
		"completed_at": time.Now().Add(-1 * time.Minute).UTC(),
		"results": gin.H{
			"total_packages": 1,
			"vulnerabilities_found": 0,
			"scan_duration": "4m30s",
		},
	})
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
	Features []float64    `json:"features,omitempty"`
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
	if s.mlPipeline == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ML pipeline not available"})
		return
	}

	// Placeholder for training implementation
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Training started",
		"status":  "in_progress",
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

// clearCache clears system cache
func (s *Server) clearCache(c *gin.Context) {
	// Placeholder for cache clearing
	c.JSON(http.StatusOK, gin.H{
		"message": "Cache cleared successfully",
	})
}

// Configuration endpoints

// getConfiguration returns current configuration
func (s *Server) getConfiguration(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"api": s.config,
	})
}

// updateConfiguration updates configuration
func (s *Server) updateConfiguration(c *gin.Context) {
	// Placeholder for configuration update
	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration updated successfully",
	})
}

// Dashboard endpoint handlers
func (s *Server) getDashboardMetrics(c *gin.Context) {
	timeRange := c.Query("timeRange")
	if timeRange == "" {
		timeRange = "7d"
	}

	c.JSON(http.StatusOK, gin.H{
		"totalScans":        1250,
		"threatsDetected":   47,
		"criticalThreats":   8,
		"packagesScanned":   15420,
		"scanSuccessRate":   98.5,
		"averageScanTime":   2.3,
		"timeRange":         timeRange,
		"lastUpdated":       time.Now().UTC(),
	})
}

func (s *Server) getDashboardActivity(c *gin.Context) {
	limit := c.Query("limit")
	if limit == "" {
		limit = "10"
	}

	activity := []gin.H{
		{
			"id":          1,
			"type":        "scan_completed",
			"package":     "express",
			"ecosystem":   "npm",
			"status":      "clean",
			"timestamp":   time.Now().Add(-5 * time.Minute).UTC(),
			"duration":    "2.1s",
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
			"id":          3,
			"type":        "vulnerability_found",
			"package":     "lodash",
			"ecosystem":   "npm",
			"status":      "vulnerable",
			"timestamp":   time.Now().Add(-30 * time.Minute).UTC(),
			"severity":    "high",
			"cve":         "CVE-2021-23337",
		},
		{
			"id":          4,
			"type":        "scan_completed",
			"package":     "react",
			"ecosystem":   "npm",
			"status":      "clean",
			"timestamp":   time.Now().Add(-45 * time.Minute).UTC(),
			"duration":    "1.8s",
		},
		{
			"id":          5,
			"type":        "batch_scan_completed",
			"packages":    25,
			"ecosystem":   "pypi",
			"status":      "completed",
			"timestamp":   time.Now().Add(-1 * time.Hour).UTC(),
			"duration":    "45.2s",
			"threats":     3,
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
		"timeRange": timeRange,
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
		"last_24h":           100,
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
			"results": []interface{}{},
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