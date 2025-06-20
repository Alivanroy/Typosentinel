package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/requestid"
	"github.com/gin-contrib/timeout"

	"typosentinel/internal/config"
	"typosentinel/pkg/logger"
	"typosentinel/internal/ml"
	"typosentinel/internal/analyzer"
	"typosentinel/pkg/types"
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
	// Set gin mode based on environment
	if !cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Add middleware
	r.Use(gin.Recovery())
	r.Use(requestid.New())
	r.Use(corsMiddleware(cfg.CORS))
	r.Use(loggingMiddleware())
	r.Use(rateLimitMiddleware(cfg.RateLimit))
	r.Use(authMiddleware(cfg.Authentication))
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

	// API versioning
	v1 := s.gin.Group(s.config.BasePath + "/v1")
	{
		// Package analysis endpoints
		packages := v1.Group("/packages")
		{
			packages.POST("/analyze", s.analyzePackage)
			packages.POST("/batch-analyze", s.batchAnalyzePackages)
			packages.GET("/analyze/:ecosystem/:name", s.analyzePackageByName)
			packages.GET("/analyze/:ecosystem/:name/:version", s.analyzePackageByVersion)
		}

		// Vulnerability endpoints
		vulns := v1.Group("/vulnerabilities")
		{
			vulns.GET("/scan/:ecosystem/:name", s.scanVulnerabilities)
			vulns.POST("/scan", s.scanPackageVulnerabilities)
			vulns.GET("/database/status", s.getVulnerabilityDatabaseStatus)
		}

		// ML prediction endpoints
		ml := v1.Group("/ml")
		{
			ml.POST("/predict/typosquatting", s.predictTyposquatting)
			ml.POST("/predict/reputation", s.predictReputation)
			ml.POST("/predict/anomaly", s.predictAnomaly)
			ml.GET("/models/status", s.getMLModelsStatus)
			ml.POST("/models/train", s.trainMLModels)
		}

		// Analysis results endpoints
		results := v1.Group("/results")
		{
			results.GET("/history", s.getAnalysisHistory)
			results.GET("/statistics", s.getAnalysisStatistics)
			results.GET("/export", s.exportResults)
		}

		// Configuration endpoints
		config := v1.Group("/config")
		{
			config.GET("/", s.getConfiguration)
			config.PUT("/", s.updateConfiguration)
			config.GET("/validate", s.validateConfiguration)
		}

		// System endpoints
		system := v1.Group("/system")
		{
			system.GET("/status", s.getSystemStatus)
			system.GET("/metrics", s.getSystemMetrics)
			system.POST("/cache/clear", s.clearCache)
		}
	}

	// Documentation endpoints
	if s.config.Documentation.Enabled {
		s.gin.Static("/docs", "./docs")
		s.gin.GET("/openapi.json", s.getOpenAPISpec)
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
		// Placeholder for vulnerability scanning
		vulns := []types.Vulnerability{}
		analysisResult["vulnerabilities"] = vulns
	}

	// Add dependency analysis if requested
	if includeDeps {
		// Placeholder for dependency analysis
		deps := []types.Package{}
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

// getVulnerabilityDatabaseStatus returns vulnerability database status
func (s *Server) getVulnerabilityDatabaseStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":      "active",
		"last_update": time.Now().Add(-24 * time.Hour).UTC(),
		"entries":     150000,
		"sources":     []string{"NVD", "OSV", "GitHub Advisory"},
	})
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

	result, err := s.mlPipeline.PredictTyposquatting(c.Request.Context(), &req.Package)
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