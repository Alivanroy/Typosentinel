package main

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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/typosentinel/typosentinel/internal/batch"
	"github.com/typosentinel/typosentinel/internal/database"
	"github.com/typosentinel/typosentinel/internal/events"
	"github.com/typosentinel/typosentinel/internal/queue"
	"github.com/typosentinel/typosentinel/internal/websocket"
	"github.com/typosentinel/pkg/config"
	"github.com/typosentinel/pkg/logger"
	"github.com/typosentinel/pkg/metrics"
)

type ScalableServer struct {
	config          *config.Config
	logger          *logger.Logger
	db              *database.Repository
	redis           *redis.Client
	scannerQueue    *queue.ScannerQueue
	batchProcessor  *batch.BatchProcessor
	eventBus        *events.EventBus
	websocketHub    *websocket.Hub
	ginEngine       *gin.Engine
	httpServer      *http.Server
}

func main() {
	server, err := NewScalableServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func NewScalableServer() (*ScalableServer, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger := logger.New(cfg.LogLevel)

	// Initialize metrics
	metrics.Init()

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Address,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		PoolSize: cfg.Redis.PoolSize,
	})

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Initialize database repository
	db, err := database.NewRepository(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize scanner queue
	scannerQueue, err := queue.NewScannerQueue(redisClient, cfg.Queue.Workers)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scanner queue: %w", err)
	}

	// Initialize batch processor
	batchProcessor := batch.NewBatchProcessor(db, cfg.Batch.Concurrency)

	// Initialize event bus
	eventBus := events.NewEventBus(redisClient)

	// Initialize WebSocket hub
	websocketHub := websocket.NewHub()

	// Setup Gin engine
	ginEngine := setupGinEngine(cfg)

	return &ScalableServer{
		config:         cfg,
		logger:         logger,
		db:             db,
		redis:          redisClient,
		scannerQueue:   scannerQueue,
		batchProcessor: batchProcessor,
		eventBus:       eventBus,
		websocketHub:   websocketHub,
		ginEngine:      ginEngine,
	}, nil
}

func setupGinEngine(cfg *config.Config) *gin.Engine {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// Middleware
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(corsMiddleware())
	r.Use(rateLimitMiddleware())
	r.Use(metricsMiddleware())

	return r
}

func (s *ScalableServer) Start() error {
	s.logger.Info("Starting Typosentinel Scalable Server")

	// Start background services
	go s.startBackgroundServices()

	// Setup routes
	s.setupRoutes()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Server.Port),
		Handler:      s.ginEngine,
		ReadTimeout:  time.Duration(s.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.config.Server.IdleTimeout) * time.Second,
	}

	// Start server in goroutine
	go func() {
		s.logger.Info(fmt.Sprintf("Server starting on port %d", s.config.Server.Port))
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error(fmt.Sprintf("Server failed to start: %v", err))
		}
	}()

	// Wait for interrupt signal
	return s.waitForShutdown()
}

func (s *ScalableServer) startBackgroundServices() {
	s.logger.Info("Starting background services")

	// Start WebSocket hub
	go s.websocketHub.Run()

	// Start scanner queue workers
	go s.scannerQueue.StartWorkers()

	// Start event bus subscribers
	go s.startEventSubscribers()

	s.logger.Info("Background services started")
}

func (s *ScalableServer) startEventSubscribers() {
	// Subscribe to package scanned events
	s.eventBus.Subscribe(events.PackageScanned, func(event *events.Event) {
		s.websocketHub.HandlePackageScanned(event)
	})

	// Subscribe to threat detected events
	s.eventBus.Subscribe(events.ThreatDetected, func(event *events.Event) {
		s.websocketHub.HandleThreatDetected(event)
		// Update metrics
		metrics.ThreatsDetected.WithLabelValues(
			event.Data["severity"].(string),
			event.Data["organization_id"].(string),
		).Inc()
	})

	// Subscribe to batch completed events
	s.eventBus.Subscribe(events.BatchCompleted, func(event *events.Event) {
		s.websocketHub.HandleBatchCompleted(event)
	})

	// Subscribe to policy violation events
	s.eventBus.Subscribe(events.PolicyViolation, func(event *events.Event) {
		s.websocketHub.HandlePolicyViolation(event)
	})
}

func (s *ScalableServer) setupRoutes() {
	// Health check
	s.ginEngine.GET("/health", s.healthCheck)
	s.ginEngine.GET("/ready", s.readinessCheck)

	// Metrics endpoint
	s.ginEngine.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API routes
	api := s.ginEngine.Group("/api/v1")
	{
		// Authentication middleware for API routes
		api.Use(s.authMiddleware())

		// Package scanning
		api.POST("/scan", s.scanPackage)
		api.POST("/scan/batch", s.scanBatch)
		api.GET("/scan/:id", s.getScanResult)
		api.GET("/scan/:id/status", s.getScanStatus)

		// Batch operations
		api.GET("/batch/:id", s.getBatchStatus)
		api.GET("/batch/:id/progress", s.getBatchProgress)

		// Organization management
		api.GET("/organizations/:id/stats", s.getOrganizationStats)
		api.GET("/organizations/:id/threats", s.getOrganizationThreats)

		// Policy management
		api.GET("/policies", s.getPolicies)
		api.POST("/policies", s.createPolicy)
		api.PUT("/policies/:id", s.updatePolicy)
		api.DELETE("/policies/:id", s.deletePolicy)

		// Analytics
		api.GET("/analytics/dashboard", s.getDashboardData)
		api.GET("/analytics/trends", s.getTrendData)
	}

	// WebSocket endpoint
	s.ginEngine.GET("/ws/:org_id", s.websocketHandler)

	// Admin routes
	admin := s.ginEngine.Group("/admin")
	{
		admin.Use(s.adminAuthMiddleware())
		admin.GET("/stats", s.getSystemStats)
		admin.GET("/queue/status", s.getQueueStatus)
		admin.POST("/queue/clear", s.clearQueue)
		admin.GET("/workers/status", s.getWorkerStatus)
	}
}

func (s *ScalableServer) healthCheck(c *gin.Context) {
	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   s.config.Version,
	}

	// Check Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.redis.Ping(ctx).Err(); err != nil {
		status["redis"] = "unhealthy"
		status["status"] = "degraded"
	} else {
		status["redis"] = "healthy"
	}

	// Check database connection
	if err := s.db.HealthCheck(); err != nil {
		status["database"] = "unhealthy"
		status["status"] = "degraded"
	} else {
		status["database"] = "healthy"
	}

	if status["status"] == "healthy" {
		c.JSON(http.StatusOK, status)
	} else {
		c.JSON(http.StatusServiceUnavailable, status)
	}
}

func (s *ScalableServer) readinessCheck(c *gin.Context) {
	// More comprehensive readiness check
	status := map[string]interface{}{
		"ready":     true,
		"timestamp": time.Now().UTC(),
	}

	// Check if workers are running
	if !s.scannerQueue.IsHealthy() {
		status["workers"] = "not ready"
		status["ready"] = false
	} else {
		status["workers"] = "ready"
	}

	// Check WebSocket hub
	if !s.websocketHub.IsHealthy() {
		status["websocket"] = "not ready"
		status["ready"] = false
	} else {
		status["websocket"] = "ready"
	}

	if status["ready"].(bool) {
		c.JSON(http.StatusOK, status)
	} else {
		c.JSON(http.StatusServiceUnavailable, status)
	}
}

func (s *ScalableServer) waitForShutdown() error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	s.logger.Info("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Error(fmt.Sprintf("Server forced to shutdown: %v", err))
		return err
	}

	// Stop background services
	s.scannerQueue.Stop()
	s.websocketHub.Stop()
	s.eventBus.Stop()

	// Close database connections
	if err := s.db.Close(); err != nil {
		s.logger.Error(fmt.Sprintf("Error closing database: %v", err))
	}

	// Close Redis connection
	if err := s.redis.Close(); err != nil {
		s.logger.Error(fmt.Sprintf("Error closing Redis: %v", err))
	}

	s.logger.Info("Server exited")
	return nil
}

// Middleware functions
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func rateLimitMiddleware() gin.HandlerFunc {
	// Implement rate limiting logic here
	return func(c *gin.Context) {
		// For now, just pass through
		c.Next()
	}
}

func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start)
		metrics.HTTPRequestDuration.WithLabelValues(
			c.Request.Method,
			c.FullPath(),
			fmt.Sprintf("%d", c.Writer.Status()),
		).Observe(duration.Seconds())

		metrics.HTTPRequestsTotal.WithLabelValues(
			c.Request.Method,
			c.FullPath(),
			fmt.Sprintf("%d", c.Writer.Status()),
		).Inc()
	}
}

func (s *ScalableServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Implement authentication logic here
		// For now, just pass through
		c.Next()
	}
}

func (s *ScalableServer) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Implement admin authentication logic here
		// For now, just pass through
		c.Next()
	}
}

func (s *ScalableServer) websocketHandler(c *gin.Context) {
	orgID := c.Param("org_id")
	userID := c.GetHeader("X-User-ID") // Get from auth middleware

	s.websocketHub.HandleWebSocket(c.Writer, c.Request, orgID, userID)
}

// Placeholder handler functions - implement based on your business logic
func (s *ScalableServer) scanPackage(c *gin.Context)         { /* TODO: Implement */ }
func (s *ScalableServer) scanBatch(c *gin.Context)           { /* TODO: Implement */ }
func (s *ScalableServer) getScanResult(c *gin.Context)       { /* TODO: Implement */ }
func (s *ScalableServer) getScanStatus(c *gin.Context)       { /* TODO: Implement */ }
func (s *ScalableServer) getBatchStatus(c *gin.Context)      { /* TODO: Implement */ }
func (s *ScalableServer) getBatchProgress(c *gin.Context)    { /* TODO: Implement */ }
func (s *ScalableServer) getOrganizationStats(c *gin.Context) { /* TODO: Implement */ }
func (s *ScalableServer) getOrganizationThreats(c *gin.Context) { /* TODO: Implement */ }
func (s *ScalableServer) getPolicies(c *gin.Context)         { /* TODO: Implement */ }
func (s *ScalableServer) createPolicy(c *gin.Context)        { /* TODO: Implement */ }
func (s *ScalableServer) updatePolicy(c *gin.Context)        { /* TODO: Implement */ }
func (s *ScalableServer) deletePolicy(c *gin.Context)        { /* TODO: Implement */ }
func (s *ScalableServer) getDashboardData(c *gin.Context)    { /* TODO: Implement */ }
func (s *ScalableServer) getTrendData(c *gin.Context)        { /* TODO: Implement */ }
func (s *ScalableServer) getSystemStats(c *gin.Context)      { /* TODO: Implement */ }
func (s *ScalableServer) getQueueStatus(c *gin.Context)      { /* TODO: Implement */ }
func (s *ScalableServer) clearQueue(c *gin.Context)          { /* TODO: Implement */ }
func (s *ScalableServer) getWorkerStatus(c *gin.Context)     { /* TODO: Implement */ }