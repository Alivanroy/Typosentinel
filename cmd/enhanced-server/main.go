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

	"github.com/typosentinel/typosentinel/internal/auth"
	"github.com/typosentinel/typosentinel/internal/autoscaler"
	"github.com/typosentinel/typosentinel/internal/batch"
	"github.com/typosentinel/typosentinel/internal/cache"
	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/database"
	"github.com/typosentinel/typosentinel/internal/events"
	"github.com/typosentinel/typosentinel/internal/gateway"
	"github.com/typosentinel/typosentinel/internal/loadbalancer"
	"github.com/typosentinel/typosentinel/internal/monitoring"
	"github.com/typosentinel/typosentinel/internal/queue"
	"github.com/typosentinel/typosentinel/internal/websocket"
	"github.com/typosentinel/typosentinel/internal/worker"
	"github.com/typosentinel/typosentinel/pkg/logger"
	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// EnhancedServer represents the enhanced scalable server with all infrastructure components
type EnhancedServer struct {
	// Core components
	logger         *logger.Logger
	db             *database.Repository
	redis          *redis.Client

	// Configuration and auth
	configManager  *config.ConfigManager
	authManager    *auth.AuthManager

	// Processing components
	scannerQueue   *queue.ScannerQueue
	batchProcessor *batch.BatchProcessor
	workerPool     *worker.WorkerPool

	// Infrastructure components
	cacheManager   *cache.CacheManager
	eventBus       *events.EventBus
	monitor        *monitoring.Monitor
	autoScaler     *autoscaler.AutoScaler
	loadBalancer   *loadbalancer.LoadBalancer
	apiGateway     *gateway.APIGateway

	// Communication
	websocketHub   *websocket.Hub

	// HTTP server
	httpServer     *http.Server

	// Lifecycle
	ctx            context.Context
	cancel         context.CancelFunc
	running        bool
}

func main() {
	server, err := NewEnhancedServer()
	if err != nil {
		log.Fatalf("Failed to create enhanced server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start enhanced server: %v", err)
	}
}

// NewEnhancedServer creates a new enhanced server with all infrastructure components
func NewEnhancedServer() (*EnhancedServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize logger first
	logger := logger.New("info")
	logger.Info("Initializing Enhanced Typosentinel Server")

	// Initialize metrics
	metrics.Init()

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
		PoolSize: 10,
	})

	// Test Redis connection
	ctxTimeout, cancelTimeout := context.WithTimeout(ctx, 5*time.Second)
	defer cancelTimeout()
	if err := redisClient.Ping(ctxTimeout).Err(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	logger.Info("Redis connection established")

	// Initialize configuration manager
	configManager, err := config.NewConfigManager(&config.ConfigManagerOptions{
		RedisClient: redisClient,
		ConfigFile:  "config.yaml",
		WatchChanges: true,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize config manager: %w", err)
	}
	logger.Info("Configuration manager initialized")

	// Load application configuration
	appConfig, err := configManager.LoadConfig()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load application config: %w", err)
	}

	// Initialize database repository
	db, err := database.NewRepository(appConfig.Database)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	logger.Info("Database repository initialized")

	// Initialize authentication manager
	authManager, err := auth.NewAuthManager(&auth.AuthConfig{
		JWTSecret:        appConfig.Security.JWTSecret,
		TokenExpiration:  appConfig.Security.TokenExpiration,
		RefreshExpiration: appConfig.Security.RefreshExpiration,
		BcryptCost:       appConfig.Security.BcryptCost,
		RateLimitEnabled: appConfig.Security.RateLimitEnabled,
	}, redisClient)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize auth manager: %w", err)
	}
	logger.Info("Authentication manager initialized")

	// Initialize cache manager
	cacheManager, err := cache.NewCacheManager(&cache.CacheConfig{
		L1Config: cache.L1Config{
			MaxSize:        appConfig.Cache.L1.MaxSize,
			MaxEntries:     appConfig.Cache.L1.MaxEntries,
			DefaultTTL:     appConfig.Cache.L1.TTL,
			EvictionPolicy: appConfig.Cache.L1.EvictionPolicy,
		},
		L2Config: cache.L2Config{
			RedisAddr:     appConfig.Redis.Address,
			RedisDB:       appConfig.Redis.DB,
			RedisPassword: appConfig.Redis.Password,
			DefaultTTL:    appConfig.Cache.L2.TTL,
			KeyPrefix:     appConfig.Cache.L2.KeyPrefix,
		},
		L3Config: cache.L3Config{
			StoragePath: appConfig.Cache.L3.StoragePath,
			MaxFileSize: appConfig.Cache.L3.MaxFileSize,
			DefaultTTL:  appConfig.Cache.L3.TTL,
			Compression: appConfig.Cache.L3.Compression,
		},
		CleanupInterval:    appConfig.Cache.CleanupInterval,
		PromotionThreshold: appConfig.Cache.PromotionThreshold,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize cache manager: %w", err)
	}
	logger.Info("Cache manager initialized")

	// Initialize event bus
	eventBus, err := events.NewEventBus(&events.EventBusConfig{
		RedisClient:     redisClient,
		MaxRetries:      appConfig.Events.MaxRetries,
		RetryDelay:      appConfig.Events.RetryDelay,
		EventTTL:        appConfig.Events.EventTTL,
		BufferSize:      appConfig.Events.BufferSize,
		WorkerCount:     appConfig.Events.WorkerCount,
		EnableHistory:   appConfig.Events.EnableHistory,
		HistorySize:     appConfig.Events.HistorySize,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize event bus: %w", err)
	}
	logger.Info("Event bus initialized")

	// Initialize monitoring
	monitor, err := monitoring.NewMonitor(&monitoring.MonitorConfig{
		RedisClient:        redisClient,
		HealthCheckInterval: appConfig.Monitoring.HealthCheckInterval,
		MetricsInterval:     appConfig.Monitoring.MetricsInterval,
		AlertThresholds:     appConfig.Monitoring.AlertThresholds,
		RetentionPeriod:     appConfig.Monitoring.RetentionPeriod,
		EnableAlerts:       appConfig.Monitoring.EnableAlerts,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize monitor: %w", err)
	}
	logger.Info("Monitoring system initialized")

	// Initialize worker pool
	workerPool, err := worker.NewWorkerPool(&worker.WorkerPoolConfig{
		MinWorkers:      appConfig.WorkerPool.MinWorkers,
		MaxWorkers:      appConfig.WorkerPool.MaxWorkers,
		ScaleUpThreshold: appConfig.WorkerPool.ScaleUpThreshold,
		ScaleDownThreshold: appConfig.WorkerPool.ScaleDownThreshold,
		IdleTimeout:     appConfig.WorkerPool.IdleTimeout,
		TaskTimeout:     appConfig.WorkerPool.TaskTimeout,
		HealthCheckInterval: appConfig.WorkerPool.HealthCheckInterval,
		MetricsInterval: appConfig.WorkerPool.MetricsInterval,
	}, eventBus)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize worker pool: %w", err)
	}
	logger.Info("Worker pool initialized")

	// Initialize scanner queue
	scannerQueue, err := queue.NewScannerQueue(redisClient, appConfig.Queue.Workers)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize scanner queue: %w", err)
	}
	logger.Info("Scanner queue initialized")

	// Initialize batch processor
	batchProcessor := batch.NewBatchProcessor(db, appConfig.Batch.Concurrency)
	logger.Info("Batch processor initialized")

	// Initialize auto scaler
	autoScaler, err := autoscaler.NewAutoScaler(&autoscaler.AutoScalerConfig{
		RedisClient:        redisClient,
		MinInstances:       appConfig.AutoScaler.MinInstances,
		MaxInstances:       appConfig.AutoScaler.MaxInstances,
		TargetCPU:          appConfig.AutoScaler.TargetCPU,
		TargetMemory:       appConfig.AutoScaler.TargetMemory,
		ScaleUpCooldown:    appConfig.AutoScaler.ScaleUpCooldown,
		ScaleDownCooldown:  appConfig.AutoScaler.ScaleDownCooldown,
		MetricsWindow:      appConfig.AutoScaler.MetricsWindow,
		CheckInterval:      appConfig.AutoScaler.CheckInterval,
	}, eventBus)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize auto scaler: %w", err)
	}
	logger.Info("Auto scaler initialized")

	// Initialize load balancer
	loadBalancer, err := loadbalancer.NewLoadBalancer(&loadbalancer.LoadBalancerConfig{
		RedisClient:     redisClient,
		Algorithm:       appConfig.LoadBalancer.Algorithm,
		HealthCheckInterval: appConfig.LoadBalancer.HealthCheckInterval,
		HealthCheckTimeout:  appConfig.LoadBalancer.HealthCheckTimeout,
		MaxRetries:      appConfig.LoadBalancer.MaxRetries,
		RetryDelay:      appConfig.LoadBalancer.RetryDelay,
		CircuitBreakerThreshold: appConfig.LoadBalancer.CircuitBreakerThreshold,
		CircuitBreakerTimeout:   appConfig.LoadBalancer.CircuitBreakerTimeout,
	}, eventBus)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize load balancer: %w", err)
	}
	logger.Info("Load balancer initialized")

	// Initialize API gateway
	apiGateway, err := gateway.NewAPIGateway(&gateway.GatewayConfig{
		RedisClient:     redisClient,
		Port:            appConfig.Gateway.Port,
		ReadTimeout:     appConfig.Gateway.ReadTimeout,
		WriteTimeout:    appConfig.Gateway.WriteTimeout,
		IdleTimeout:     appConfig.Gateway.IdleTimeout,
		MaxHeaderBytes:  appConfig.Gateway.MaxHeaderBytes,
		EnableCORS:      appConfig.Gateway.EnableCORS,
		EnableMetrics:   appConfig.Gateway.EnableMetrics,
		RateLimitEnabled: appConfig.Gateway.RateLimitEnabled,
		AuthRequired:    appConfig.Gateway.AuthRequired,
	}, authManager, eventBus)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize API gateway: %w", err)
	}
	logger.Info("API gateway initialized")

	// Initialize WebSocket hub
	websocketHub := websocket.NewHub()
	logger.Info("WebSocket hub initialized")

	server := &EnhancedServer{
		logger:         logger,
		db:             db,
		redis:          redisClient,
		configManager:  configManager,
		authManager:    authManager,
		scannerQueue:   scannerQueue,
		batchProcessor: batchProcessor,
		workerPool:     workerPool,
		cacheManager:   cacheManager,
		eventBus:       eventBus,
		monitor:        monitor,
		autoScaler:     autoScaler,
		loadBalancer:   loadBalancer,
		apiGateway:     apiGateway,
		websocketHub:   websocketHub,
		ctx:            ctx,
		cancel:         cancel,
	}

	logger.Info("Enhanced server initialization completed")
	return server, nil
}

// Start starts all server components
func (s *EnhancedServer) Start() error {
	s.logger.Info("Starting Enhanced Typosentinel Server")
	s.running = true

	// Start infrastructure components
	if err := s.startInfrastructure(); err != nil {
		return fmt.Errorf("failed to start infrastructure: %w", err)
	}

	// Start processing components
	if err := s.startProcessing(); err != nil {
		return fmt.Errorf("failed to start processing components: %w", err)
	}

	// Start API gateway
	if err := s.apiGateway.Start(); err != nil {
		return fmt.Errorf("failed to start API gateway: %w", err)
	}

	// Setup health monitoring
	s.setupHealthMonitoring()

	// Setup event subscriptions
	s.setupEventSubscriptions()

	s.logger.Info("Enhanced server started successfully")

	// Wait for shutdown signal
	return s.waitForShutdown()
}

// startInfrastructure starts all infrastructure components
func (s *EnhancedServer) startInfrastructure() error {
	s.logger.Info("Starting infrastructure components")

	// Start cache manager
	if err := s.cacheManager.Start(); err != nil {
		return fmt.Errorf("failed to start cache manager: %w", err)
	}

	// Start event bus
	if err := s.eventBus.Start(); err != nil {
		return fmt.Errorf("failed to start event bus: %w", err)
	}

	// Start monitoring
	if err := s.monitor.Start(); err != nil {
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	// Start authentication manager
	if err := s.authManager.Start(); err != nil {
		return fmt.Errorf("failed to start auth manager: %w", err)
	}

	// Start load balancer
	if err := s.loadBalancer.Start(); err != nil {
		return fmt.Errorf("failed to start load balancer: %w", err)
	}

	// Start auto scaler
	if err := s.autoScaler.Start(); err != nil {
		return fmt.Errorf("failed to start auto scaler: %w", err)
	}

	s.logger.Info("Infrastructure components started")
	return nil
}

// startProcessing starts all processing components
func (s *EnhancedServer) startProcessing() error {
	s.logger.Info("Starting processing components")

	// Start worker pool
	if err := s.workerPool.Start(); err != nil {
		return fmt.Errorf("failed to start worker pool: %w", err)
	}

	// Start scanner queue workers
	go s.scannerQueue.StartWorkers()

	// Start WebSocket hub
	go s.websocketHub.Run()

	s.logger.Info("Processing components started")
	return nil
}

// setupHealthMonitoring sets up health checks for all components
func (s *EnhancedServer) setupHealthMonitoring() {
	s.logger.Info("Setting up health monitoring")

	// Add health checks for all components
	s.monitor.AddHealthCheck("redis", func() monitoring.HealthCheckResult {
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
		defer cancel()
		err := s.redis.Ping(ctx).Err()
		return monitoring.HealthCheckResult{
			Healthy: err == nil,
			Message: fmt.Sprintf("Redis health: %v", err),
			CheckedAt: time.Now(),
		}
	})

	s.monitor.AddHealthCheck("database", func() monitoring.HealthCheckResult {
		err := s.db.HealthCheck()
		return monitoring.HealthCheckResult{
			Healthy: err == nil,
			Message: fmt.Sprintf("Database health: %v", err),
			CheckedAt: time.Now(),
		}
	})

	s.monitor.AddHealthCheck("worker_pool", func() monitoring.HealthCheckResult {
		healthy := s.workerPool.IsRunning()
		return monitoring.HealthCheckResult{
			Healthy: healthy,
			Message: fmt.Sprintf("Worker pool running: %v", healthy),
			CheckedAt: time.Now(),
		}
	})

	s.monitor.AddHealthCheck("cache_manager", func() monitoring.HealthCheckResult {
		healthy := s.cacheManager.IsRunning()
		return monitoring.HealthCheckResult{
			Healthy: healthy,
			Message: fmt.Sprintf("Cache manager running: %v", healthy),
			CheckedAt: time.Now(),
		}
	})

	s.monitor.AddHealthCheck("event_bus", func() monitoring.HealthCheckResult {
		healthy := s.eventBus.IsRunning()
		return monitoring.HealthCheckResult{
			Healthy: healthy,
			Message: fmt.Sprintf("Event bus running: %v", healthy),
			CheckedAt: time.Now(),
		}
	})

	s.monitor.AddHealthCheck("api_gateway", func() monitoring.HealthCheckResult {
		healthy := s.apiGateway.IsRunning()
		return monitoring.HealthCheckResult{
			Healthy: healthy,
			Message: fmt.Sprintf("API gateway running: %v", healthy),
			CheckedAt: time.Now(),
		}
	})
}

// setupEventSubscriptions sets up event subscriptions
func (s *EnhancedServer) setupEventSubscriptions() {
	s.logger.Info("Setting up event subscriptions")

	// Subscribe to scan events
	s.eventBus.Subscribe("scan.completed", func(event *events.Event) {
		s.logger.Info(fmt.Sprintf("Scan completed: %s", event.ID))
		// Update cache with scan results
		if scanResult, ok := event.Data["result"]; ok {
			cacheKey := fmt.Sprintf("scan:%s", event.Data["package_name"])
			s.cacheManager.Set(cacheKey, scanResult, 1*time.Hour)
		}
		// Notify WebSocket clients
		s.websocketHub.Broadcast(event)
	})

	// Subscribe to threat detection events
	s.eventBus.Subscribe("threat.detected", func(event *events.Event) {
		s.logger.Warn(fmt.Sprintf("Threat detected: %s", event.ID))
		// Trigger alert
		s.monitor.TriggerAlert(monitoring.Alert{
			ID:       fmt.Sprintf("threat-%s", event.ID),
			Level:    monitoring.AlertLevelHigh,
			Message:  fmt.Sprintf("Threat detected in package: %s", event.Data["package_name"]),
			Source:   "threat_detector",
			Metadata: event.Data,
			Timestamp: time.Now(),
		})
		// Notify WebSocket clients
		s.websocketHub.Broadcast(event)
	})

	// Subscribe to worker events
	s.eventBus.Subscribe("worker.scaled", func(event *events.Event) {
		s.logger.Info(fmt.Sprintf("Worker pool scaled: %s", event.Data["action"]))
	})

	// Subscribe to system events
	s.eventBus.Subscribe("system.health", func(event *events.Event) {
		if status, ok := event.Data["status"].(string); ok && status == "unhealthy" {
			s.monitor.TriggerAlert(monitoring.Alert{
				ID:       fmt.Sprintf("health-%s", event.ID),
				Level:    monitoring.AlertLevelMedium,
				Message:  fmt.Sprintf("System health issue: %s", event.Data["component"]),
				Source:   "health_monitor",
				Metadata: event.Data,
				Timestamp: time.Now(),
			})
		}
	})
}

// waitForShutdown waits for shutdown signal and gracefully shuts down
func (s *EnhancedServer) waitForShutdown() error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	s.logger.Info("Shutting down Enhanced Typosentinel Server...")

	return s.Shutdown()
}

// Shutdown gracefully shuts down all server components
func (s *EnhancedServer) Shutdown() error {
	if !s.running {
		return nil
	}

	s.running = false
	s.cancel()

	s.logger.Info("Stopping server components...")

	// Stop API gateway first
	if err := s.apiGateway.Shutdown(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping API gateway: %v", err))
	}

	// Stop processing components
	if err := s.workerPool.Stop(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping worker pool: %v", err))
	}

	s.scannerQueue.Stop()
	s.websocketHub.Stop()

	// Stop infrastructure components
	if err := s.autoScaler.Stop(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping auto scaler: %v", err))
	}

	if err := s.loadBalancer.Stop(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping load balancer: %v", err))
	}

	if err := s.monitor.Stop(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping monitor: %v", err))
	}

	if err := s.eventBus.Shutdown(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping event bus: %v", err))
	}

	if err := s.cacheManager.Shutdown(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping cache manager: %v", err))
	}

	if err := s.authManager.Shutdown(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping auth manager: %v", err))
	}

	if err := s.configManager.Shutdown(); err != nil {
		s.logger.Error(fmt.Sprintf("Error stopping config manager: %v", err))
	}

	// Close database connections
	if err := s.db.Close(); err != nil {
		s.logger.Error(fmt.Sprintf("Error closing database: %v", err))
	}

	// Close Redis connection
	if err := s.redis.Close(); err != nil {
		s.logger.Error(fmt.Sprintf("Error closing Redis: %v", err))
	}

	s.logger.Info("Enhanced server shutdown completed")
	return nil
}

// IsRunning returns whether the server is running
func (s *EnhancedServer) IsRunning() bool {
	return s.running
}

// GetStats returns comprehensive server statistics
func (s *EnhancedServer) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Worker pool stats
	stats["worker_pool"] = s.workerPool.GetStats()

	// Cache stats
	stats["cache"] = s.cacheManager.GetStats()

	// Event bus stats
	stats["event_bus"] = s.eventBus.GetStats()

	// Monitoring stats
	stats["monitoring"] = map[string]interface{}{
		"health_status": s.monitor.GetHealthStatus(),
		"alerts":        s.monitor.GetAlerts(),
	}

	// System metrics
	stats["system"] = s.monitor.GetSystemMetrics()

	return stats
}

// GetHealthStatus returns the overall health status
func (s *EnhancedServer) GetHealthStatus() monitoring.HealthStatus {
	return s.monitor.GetOverallHealth()
}