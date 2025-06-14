package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/typosentinel/typosentinel/internal/analyzer"
	"github.com/typosentinel/typosentinel/internal/auth"
	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/database"
	"github.com/typosentinel/typosentinel/pkg/ml"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	TLSCertFile  string
	TLSKeyFile   string
	DebugMode    bool
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Host:         "localhost",
		Port:         8080,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		DebugMode:    false,
	}
}

// APIServer represents the main API server
type APIServer struct {
	config   *ServerConfig
	server   *http.Server
	analyzer *analyzer.Analyzer
	db       *database.Database
	mlClient *ml.Client
	handler  *Server
}

// NewAPIServer creates a new API server instance
func NewAPIServer(cfg *config.Config) (*APIServer, error) {
	// Initialize database
	dbConfig := database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		DBName:   cfg.Database.Name,
		SSLMode:  cfg.Database.SSLMode,
	}
	db, err := database.New(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Run database migrations
	if err := db.Migrate(); err != nil {
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	// Initialize ML client
	apiKey := os.Getenv("TYPOSENTINEL_API_KEY")
	if apiKey == "" {
		apiKey = "dev-key-123" // Default development key
	}
	mlClient := ml.NewClient(cfg.MLService.Endpoint, apiKey)

	// Initialize analyzer
	analyzer := analyzer.New(cfg)

	// Initialize auth services (simplified for now)
	authService := &auth.AuthService{}
	userService := &auth.UserService{}
	orgService := &auth.OrganizationService{}

	// Create API handler
	handler := NewServer(analyzer, db, mlClient, authService, userService, orgService)

	// Configure server
	serverConfig := &ServerConfig{
		Host:         cfg.API.Host,
		Port:         cfg.API.Port,
		ReadTimeout:  30 * time.Second,  // Default timeout
		WriteTimeout: 30 * time.Second,  // Default timeout
		IdleTimeout:  60 * time.Second,  // Default timeout
		TLSCertFile:  cfg.API.TLS.CertFile,
		TLSKeyFile:   cfg.API.TLS.KeyFile,
		DebugMode:    cfg.Debug,
	}

	// Set Gin mode
	if !serverConfig.DebugMode {
		gin.SetMode(gin.ReleaseMode)
	}

	return &APIServer{
		config:   serverConfig,
		analyzer: analyzer,
		db:       db,
		mlClient: mlClient,
		handler:  handler,
	}, nil
}

// Start starts the API server
func (s *APIServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.handler.GetRouter(),
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	log.Printf("Starting API server on %s", addr)

	// Start server
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		log.Printf("Starting HTTPS server with TLS")
		return s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	} else {
		log.Printf("Starting HTTP server (no TLS)")
		return s.server.ListenAndServe()
	}
}

// Stop gracefully stops the API server
func (s *APIServer) Stop(ctx context.Context) error {
	log.Println("Shutting down API server...")

	// Shutdown server
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	// Close database connection
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}

	log.Println("API server stopped")
	return nil
}

// StartWithGracefulShutdown starts the server and handles graceful shutdown
func (s *APIServer) StartWithGracefulShutdown() error {
	// Create a channel to receive OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if err := s.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Println("API server started. Press Ctrl+C to stop.")

	// Wait for interrupt signal
	<-sigChan

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	return s.Stop(ctx)
}

// Health check endpoint data
type HealthStatus struct {
	Status    string                 `json:"status"`
	Timestamp time.Time             `json:"timestamp"`
	Version   string                 `json:"version"`
	Services  map[string]interface{} `json:"services"`
	Uptime    time.Duration          `json:"uptime"`
}

// GetHealthStatus returns the current health status
func (s *APIServer) GetHealthStatus() *HealthStatus {
	services := map[string]interface{}{
		"database": map[string]interface{}{
			"connected": s.db != nil,
			"status":    "healthy",
		},
		"ml_service": map[string]interface{}{
			"connected": s.mlClient != nil,
			"status":    "healthy",
		},
		"analyzer": map[string]interface{}{
			"initialized": s.analyzer != nil,
			"status":      "healthy",
		},
	}

	// Check ML service health
	if s.mlClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if _, err := s.mlClient.GetModels(ctx); err != nil {
			services["ml_service"] = map[string]interface{}{
				"connected": false,
				"status":    "unhealthy",
				"error":     err.Error(),
			}
		}
	}

	return &HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now().UTC(),
		Version:   "1.0.0",
		Services:  services,
		Uptime:    time.Since(time.Now()), // This should be calculated from server start time
	}
}

// Middleware for request logging
func RequestLoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// Middleware for rate limiting (basic implementation)
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement proper rate limiting
		// For now, this is a placeholder
		c.Next()
	}
}

// Middleware for request size limiting
func RequestSizeLimitMiddleware(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request body too large",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Middleware for security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

// setupRoutes configures all API routes
func (s *APIServer) setupRoutes() {
	// Health check
	s.router.HandleFunc("/health", s.HealthCheck).Methods("GET")

	// API routes
	api := s.router.PathPrefix("/api").Subrouter()

	// Authentication routes
	api.HandleFunc("/auth/login", s.Login).Methods("POST")
	api.HandleFunc("/auth/register", s.Register).Methods("POST")
	api.HandleFunc("/auth/refresh", s.RefreshToken).Methods("POST")

	// Protected routes
	protected := api.PathPrefix("").Subrouter()
	protected.Use(s.authMiddleware)

	// Package routes
	protected.HandleFunc("/packages", s.GetPackages).Methods("GET")
	protected.HandleFunc("/packages/{name}", s.GetPackage).Methods("GET")
	protected.HandleFunc("/packages/{name}/analyze", s.AnalyzePackage).Methods("POST")

	// Scan routes
	protected.HandleFunc("/scans", s.GetScans).Methods("GET")
	protected.HandleFunc("/scans", s.CreateScan).Methods("POST")
	protected.HandleFunc("/scans/{id}", s.GetScan).Methods("GET")

	// User routes
	protected.HandleFunc("/user/profile", s.GetProfile).Methods("GET")
	protected.HandleFunc("/user/profile", s.UpdateProfile).Methods("PUT")

	// Organization routes
	protected.HandleFunc("/organizations/{id}", s.GetOrganization).Methods("GET")
	protected.HandleFunc("/organizations/{id}/settings", s.UpdateOrganizationSettings).Methods("PUT")
	protected.HandleFunc("/organizations/{id}/registries", s.GetCustomRegistries).Methods("GET")
	protected.HandleFunc("/organizations/{id}/registries", s.CreateCustomRegistry).Methods("POST")
	protected.HandleFunc("/organizations/{id}/registries/{registryId}", s.UpdateCustomRegistry).Methods("PUT")
	protected.HandleFunc("/organizations/{id}/registries/{registryId}", s.DeleteCustomRegistry).Methods("DELETE")
	protected.HandleFunc("/organizations/{id}/registries/{registryId}/test", s.TestCustomRegistry).Methods("POST")
	protected.HandleFunc("/organizations/{id}/stats", s.GetOrganizationStats).Methods("GET")

	// Project routes
	protected.HandleFunc("/projects", s.GetProjects).Methods("GET")
	protected.HandleFunc("/projects", s.CreateProject).Methods("POST")
	protected.HandleFunc("/projects/{id}", s.GetProject).Methods("GET")
	protected.HandleFunc("/projects/{id}", s.UpdateProject).Methods("PUT")
	protected.HandleFunc("/projects/{id}", s.DeleteProject).Methods("DELETE")
	protected.HandleFunc("/projects/{id}/scan", s.ScanProject).Methods("POST")
	protected.HandleFunc("/projects/{id}/scans", s.GetProjectScans).Methods("GET")
	protected.HandleFunc("/projects/{id}/dependencies", s.GetProjectDependencyTree).Methods("GET")
	protected.HandleFunc("/projects/{id}/stats", s.GetProjectStats).Methods("GET")
}