package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/typosentinel/typosentinel/internal/analyzer"
	"github.com/typosentinel/typosentinel/internal/auth"
	"github.com/typosentinel/typosentinel/internal/database"
	"github.com/typosentinel/typosentinel/pkg/ml"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// Server represents the API server
type Server struct {
	analyzer    *analyzer.Analyzer
	db          *database.Database
	mlClient    *ml.Client
	authService *auth.AuthService
	userService *auth.UserService
	orgService  *auth.OrganizationService
	router      *gin.Engine
}

// NewServer creates a new API server
func NewServer(analyzer *analyzer.Analyzer, db *database.Database, mlClient *ml.Client, authService *auth.AuthService, userService *auth.UserService, orgService *auth.OrganizationService) *Server {
	s := &Server{
		analyzer:    analyzer,
		db:          db,
		mlClient:    mlClient,
		authService: authService,
		userService: userService,
		orgService:  orgService,
	}

	s.setupRoutes()
	return s
}

// Start starts the HTTP server
func (s *Server) Start(addr string) error {
	return s.router.Run(addr)
}

// setupRoutes configures the API routes
func (s *Server) setupRoutes() {
	s.router = gin.Default()

	// Middleware
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())
	s.router.Use(s.corsMiddleware())

	// Health check
	s.router.GET("/health", s.healthCheck)

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Public endpoints (no auth required)
		v1.GET("/registries", s.listRegistries)
		v1.GET("/version", s.getVersion)

		// Authentication endpoints (public)
		auth := v1.Group("/auth")
		{
			auth.POST("/login", s.login)
			auth.POST("/refresh", s.refreshToken)
			auth.POST("/logout", s.logout)
		}

		// Protected routes (require authentication)
		protected := v1.Group("/")
		protected.Use(s.authMiddleware())
		{
			// User management endpoints
			users := protected.Group("/users")
			{
				users.GET("/me", s.getCurrentUser)
				users.PUT("/me", s.updateUser)
				users.POST("/me/change-password", s.changePassword)
				users.GET("/", s.requirePermission("user:read"), s.listUsers)
				users.POST("/", s.requirePermission("user:create"), s.createUser)
				users.GET("/:id", s.getUser)
				users.PUT("/:id", s.updateUser)
				users.DELETE("/:id", s.requirePermission("user:delete"), s.deleteUser)
			}

			// Organization management endpoints
			orgs := protected.Group("/organizations")
			{
				orgs.GET("/me", s.getCurrentOrganization)
				orgs.PUT("/me", s.requirePermission("org:update"), s.updateOrganization)
				orgs.GET("/me/stats", s.getOrganizationStats)
				// Organization endpoints will be implemented later
			}

			// Scan endpoints
			scans := protected.Group("/scans")
			{
				scans.POST("/", s.createScan)
				scans.GET("/", s.listScans)
				scans.GET("/:id", s.getScan)
				scans.DELETE("/:id", s.deleteScan)
			}

			// IDE-specific scan endpoints (Phase 1 implementation)
			scan := protected.Group("/scan")
			{
				scan.POST("/ide", s.scanDependenciesIDE)
			}

			// Package endpoints
			packages := protected.Group("/packages")
			{
				packages.GET("/:registry/:name", s.getPackage)
				packages.GET("/:registry/:name/:version", s.getPackageVersion)
			}
		}
	}
}

// GetRouter returns the gin router
func (s *Server) GetRouter() *gin.Engine {
	return s.router
}

// Middleware functions

func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check Bearer token format
		if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format. Use 'Bearer <token>'"})
			c.Abort()
			return
		}

		// Extract token
		token := authHeader[7:]

		// Validate JWT token
		claims, err := s.authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("organization_id", claims.OrganizationID)
		c.Set("user_role", claims.Role)
		c.Set("user_permissions", claims.Permissions)
		c.Set("claims", claims)

		c.Next()
	}
}

// requirePermission method is defined in auth_handlers.go

// Handler functions

func (s *Server) healthCheck(c *gin.Context) {
	status := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
		"services": gin.H{
			"analyzer": s.analyzer != nil,
			"database": s.db != nil,
			"ml_client": s.mlClient != nil,
		},
	}

	c.JSON(http.StatusOK, status)
}

func (s *Server) createScan(c *gin.Context) {
	var request types.ScanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set request metadata
	request.ID = uuid.New().String()
	request.Status = types.ScanStatusPending
	now := time.Now()
	request.CreatedAt = now

	// Get user context
	userID, _ := c.Get("user_id")
	orgID, _ := c.Get("organization_id")
	request.UserID = userID.(string)
	request.OrganizationID = orgID.(string)

	// Save scan request to database
	if err := s.db.SaveScanRequest(c.Request.Context(), &request); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save scan request"})
		return
	}

	// Start scan asynchronously
	go s.performScan(context.Background(), &request)

	c.JSON(http.StatusCreated, gin.H{
		"scan_id": request.ID,
		"status":  request.Status,
		"message": "Scan started successfully",
	})
}

func (s *Server) getScan(c *gin.Context) {
	scanID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	// Get scan request
	scanRequest, err := s.db.GetScanRequest(c.Request.Context(), scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Get scan results
	results, err := s.db.GetScanResults(c.Request.Context(), scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scan results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_request": scanRequest,
		"results":      results,
	})
}

func (s *Server) listScans(c *gin.Context) {
	// Get pagination parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// Get user context
	userID, _ := c.Get("user_id")
	userUUID := uuid.MustParse(userID.(string))

	// Get user scans
	scans, err := s.db.GetUserScans(c.Request.Context(), userUUID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scans"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scans":  scans,
		"limit":  limit,
		"offset": offset,
		"total":  len(scans),
	})
}

func (s *Server) deleteScan(c *gin.Context) {
	// TODO: Implement scan deletion
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

func (s *Server) getPackage(c *gin.Context) {
	registry := c.Param("registry")
	name := c.Param("name")

	// TODO: Get package information from registry
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":    "Not implemented",
		"registry": registry,
		"name":     name,
	})
}

func (s *Server) getPackageVersion(c *gin.Context) {
	registry := c.Param("registry")
	name := c.Param("name")
	version := c.Param("version")

	// Get package metadata from database
	metadata, err := s.db.GetPackageMetadata(c.Request.Context(), name, registry, version)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Package not found"})
		return
	}

	c.JSON(http.StatusOK, metadata)
}

func (s *Server) listThreats(c *gin.Context) {
	// Get query parameters
	scanID := c.Query("scan_id")
	severity := c.Query("severity")
	threatType := c.Query("type")

	// TODO: Implement threat filtering and listing
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":      "Not implemented",
		"scan_id":    scanID,
		"severity":   severity,
		"threat_type": threatType,
	})
}

func (s *Server) getThreatStats(c *gin.Context) {
	// Get query parameters
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))

	// Get user context
	orgID, _ := c.Get("organization_id")
	orgUUID := uuid.MustParse(orgID.(string))

	// Get threat statistics
	stats, err := s.db.GetThreatStatistics(c.Request.Context(), &orgUUID, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get threat statistics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"statistics": stats,
		"period":     fmt.Sprintf("%d days", days),
	})
}

func (s *Server) findSimilarPackages(c *gin.Context) {
	var request struct {
		PackageName string `json:"package_name" binding:"required"`
		Registry    string `json:"registry"`
		TopK        int    `json:"top_k"`
		Threshold   float64 `json:"threshold"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if request.Registry == "" {
		request.Registry = "npm"
	}
	if request.TopK == 0 {
		request.TopK = 10
	}
	if request.Threshold == 0 {
		request.Threshold = 0.7
	}

	// Call ML service
	response, err := s.mlClient.FindSimilarPackages(
		c.Request.Context(),
		request.PackageName,
		[]string{}, // candidates - empty for now
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find similar packages"})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (s *Server) checkMaliciousPackage(c *gin.Context) {
	var request struct {
		PackageName string `json:"package_name" binding:"required"`
		Registry    string `json:"registry"`
		Version     string `json:"version"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if request.Registry == "" {
		request.Registry = "npm"
	}

	// Call ML service
	metadata := map[string]interface{}{
		"registry": request.Registry,
		"version":  request.Version,
	}
	response, err := s.mlClient.CheckMaliciousPackage(
		c.Request.Context(),
		request.PackageName,
		metadata,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check malicious package"})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (s *Server) getMLModels(c *gin.Context) {
	// Get ML models information
	models, err := s.mlClient.GetModels(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get ML models"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"models": models})
}

func (s *Server) listPolicies(c *gin.Context) {
	// TODO: Implement policy listing
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

func (s *Server) createPolicy(c *gin.Context) {
	// TODO: Implement policy creation
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

func (s *Server) updatePolicy(c *gin.Context) {
	// TODO: Implement policy update
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

func (s *Server) deletePolicy(c *gin.Context) {
	// TODO: Implement policy deletion
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

func (s *Server) listRegistries(c *gin.Context) {
	registries := []gin.H{
		{
			"name":        "npm",
			"description": "Node Package Manager",
			"url":         "https://registry.npmjs.org",
			"supported":   true,
		},
		{
			"name":        "pypi",
			"description": "Python Package Index",
			"url":         "https://pypi.org",
			"supported":   true,
		},
		{
			"name":        "go",
			"description": "Go Module Proxy",
			"url":         "https://proxy.golang.org",
			"supported":   true,
		},
		{
			"name":        "cargo",
			"description": "Rust Package Registry",
			"url":         "https://crates.io",
			"supported":   false,
		},
		{
			"name":        "rubygems",
			"description": "Ruby Package Manager",
			"url":         "https://rubygems.org",
			"supported":   false,
		},
	}

	c.JSON(http.StatusOK, gin.H{"registries": registries})
}

func (s *Server) getVersion(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"version":     "1.0.0",
		"build_time":  time.Now().Format(time.RFC3339),
		"go_version":  "1.21",
		"api_version": "v1",
	})
}

// IDE scan endpoint handler (Phase 1 implementation)
func (s *Server) scanDependenciesIDE(c *gin.Context) {
	var request struct {
		Ecosystem string `json:"ecosystem" binding:"required"`
		Packages  []struct {
			Name    string `json:"name" binding:"required"`
			Version string `json:"version" binding:"required"`
		} `json:"packages" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate ecosystem
	validEcosystems := map[string]bool{
		"npm":      true,
		"pypi":     true,
		"go":       true,
		"maven":    true,
		"gradle":   true,
		"composer": true,
		"cargo":    true,
	}

	if !validEcosystems[request.Ecosystem] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported ecosystem"})
		return
	}

	// Prepare response
	response := struct {
		Findings []struct {
			PackageName string  `json:"packageName"`
			Severity    string  `json:"severity"`
			Type        string  `json:"type"`
			Description string  `json:"description"`
			CVE         *string `json:"cve"`
		} `json:"findings"`
	}{}

	// Scan each package for typosquatting and vulnerabilities
	for _, pkg := range request.Packages {
		// Check for known typosquats (Phase 1 implementation)
		if s.isKnownTyposquat(pkg.Name, request.Ecosystem) {
			finding := struct {
				PackageName string  `json:"packageName"`
				Severity    string  `json:"severity"`
				Type        string  `json:"type"`
				Description string  `json:"description"`
				CVE         *string `json:"cve"`
			}{
				PackageName: pkg.Name,
				Severity:    "Critical",
				Type:        "Typosquatting",
				Description: fmt.Sprintf("The package '%s' is a suspected typosquat. This package may contain malicious code and should not be used.", pkg.Name),
				CVE:         nil,
			}
			response.Findings = append(response.Findings, finding)
		}

		// TODO: Add vulnerability scanning using the existing analyzer
		// This will be implemented in Phase 2
	}

	c.JSON(http.StatusOK, response)
}

// Helper function to check for known typosquats (Phase 1 implementation)
func (s *Server) isKnownTyposquat(packageName, ecosystem string) bool {
	// Known typosquats for demonstration (Phase 1)
	knownTyposquats := map[string][]string{
		"npm": {
			"lodahs", "expres", "recat", "vue-js", "angualr",
			"jquery-ui", "bootstrp", "momnet", "undersocre",
		},
		"pypi": {
			"djnago", "flsk", "reqeusts", "numpay", "pandsa",
			"matplotlb", "scippy", "beautfulsoup4",
		},
		"go": {
			"gorm.io/grom", "github.com/gin-gnic/gin",
			"github.com/gorila/mux",
		},
		"maven": {
			"org.springframwork.boot", "com.fasterxml.jackson.cor",
		},
		"composer": {
			"laravl/framework", "sympfony/console",
		},
		"cargo": {
			"sred", "tokio-rs", "clapp",
		},
	}

	if typosquats, exists := knownTyposquats[ecosystem]; exists {
		for _, typo := range typosquats {
			if typo == packageName {
				return true
			}
		}
	}
	return false
}

// Helper functions

func (s *Server) performScan(ctx context.Context, request *types.ScanRequest) {
	// Parse scan ID
	scanID, _ := uuid.Parse(request.ID)
	
	// Update status to running
	s.db.UpdateScanRequest(ctx, scanID, types.ScanStatusRunning, "")

	// Perform the actual scan
	options := &analyzer.ScanOptions{
		IncludeDevDependencies: request.Options.IncludeDevDependencies,
		SimilarityThreshold:    request.Options.SimilarityThreshold,
		ExcludePackages:        request.Options.ExcludePackages,
		DeepAnalysis:           request.Options.DeepAnalysis,
	}

	result, err := s.analyzer.Scan(request.Path, options)
	if err != nil {
		// Update status to failed
		s.db.UpdateScanRequest(ctx, scanID, types.ScanStatusFailed, err.Error())
		return
	}

	// Convert analyzer result to scan response
	scanResponse := &types.ScanResponse{
		ID:             uuid.New().String(),
		ScanID:         request.ID,
		PackageName:    "", // Will be populated from scan metadata
		PackageVersion: "", // Will be populated from scan metadata
		Registry:       "", // Will be populated from scan metadata
		Threats:        result.Threats,
		Warnings:       result.Warnings,
		Summary:        &types.ScanSummary{
			TotalPackages:   result.TotalPackages,
			TotalThreats:    len(result.Threats),
			HighestSeverity: types.SeverityLow, // Default, will be calculated
		},
		Timestamp:      result.Timestamp,
	}

	// Save scan result
	if err := s.db.SaveScanResult(ctx, scanResponse); err != nil {
		// Update status to failed
		s.db.UpdateScanRequest(ctx, scanID, types.ScanStatusFailed, err.Error())
		return
	}

	// Update status to completed
	s.db.UpdateScanRequest(ctx, scanID, types.ScanStatusCompleted, "")
}