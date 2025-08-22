package optimization

import (
	"context"
	"log"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ExampleBasicOptimization demonstrates basic optimization setup and usage
func ExampleBasicOptimization() {
	// Initialize database
	dbConfig := &config.DatabaseConfig{
		Type: "sqlite",
		Database: ":memory:",
	}
	db, err := database.NewThreatDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager with production settings
	optManager, err := QuickOptimizationSetup(db)
	if err != nil {
		log.Fatalf("Failed to create optimization manager: %v", err)
	}

	// Start optimization
	if err := optManager.Start(); err != nil {
		log.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Perform optimized threat lookup
	threat, err := optManager.OptimizedThreatLookup("malicious-package", "npm")
	if err != nil {
		log.Printf("Threat lookup error: %v", err)
	} else if threat != nil {
		log.Printf("Found threat: %s", threat.Description)
	} else {
		log.Println("No threat found")
	}

	// Get optimization statistics
	stats := optManager.GetOptimizationStats()
	if stats != nil {
		log.Printf("Cache hit ratio: %.2f%%", stats.Cache.OverallHitRatio*100)
		log.Printf("Average query time: %v", stats.Database.AvgQueryTime)
		log.Printf("Memory usage: %d MB", stats.Resource.MemoryUsage/(1024*1024))
	}

	// Generate optimization report
	report := optManager.GenerateOptimizationReport()
	if report != nil {
		log.Printf("Generated report with %d recommendations", len(report.Recommendations))
		log.Printf("Active alerts: %d", len(report.Alerts))
		log.Printf("Detected bottlenecks: %d", len(report.Bottlenecks))
	}
}

// ExampleBatchOptimization demonstrates batch processing optimization
func ExampleBatchOptimization() {
	// Initialize database
	dbConfig := &config.DatabaseConfig{
		Type: "sqlite",
		Database: ":memory:",
	}
	db, err := database.NewThreatDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager
	optManager, err := NewOptimizationManager(db, "production")
	if err != nil {
		log.Fatalf("Failed to create optimization manager: %v", err)
	}

	// Start optimization
	if err := optManager.Start(); err != nil {
		log.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Prepare batch of packages to check
	packages := []types.Package{
		{Name: "express", Version: "4.18.0", Registry: "npm"},
		{Name: "lodash", Version: "4.17.21", Registry: "npm"},
		{Name: "react", Version: "18.2.0", Registry: "npm"},
		{Name: "axios", Version: "1.4.0", Registry: "npm"},
		{Name: "moment", Version: "2.29.4", Registry: "npm"},
	}

	// Perform batch optimized threat lookup
	start := time.Now()
	threats, err := optManager.BatchOptimizedThreatLookup(packages)
	duration := time.Since(start)

	if err != nil {
		log.Printf("Batch lookup error: %v", err)
		return
	}

	log.Printf("Batch lookup completed in %v", duration)
	log.Printf("Checked %d packages, found %d threats", len(packages), len(threats))

	// Display results
	for _, threat := range threats {
		if threat != nil {
			log.Printf("Threat found in %s: %s", threat.PackageName, threat.Description)
		}
	}

	// Check optimization effectiveness
	stats := optManager.GetOptimizationStats()
	if stats != nil {
		log.Printf("Batch efficiency: %.2f%%", stats.Database.BatchEfficiency*100)
		log.Printf("Cache utilization: %.2f%%", stats.Cache.OverallHitRatio*100)
	}
}

// ExampleAdvancedOptimization demonstrates advanced optimization features
func ExampleAdvancedOptimization() {
	// Initialize database
	dbConfig := &config.DatabaseConfig{
		Type: "sqlite",
		Database: ":memory:",
	}
	db, err := database.NewThreatDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create custom configuration
	config := &PerformanceConfig{
		Database: &OptimizationConfig{
			CacheMaxSize:       1000,
			BatchSize:          100,
			ConnectionPoolSize: 20,
			QueryTimeout:       10 * time.Second,
			CacheTTL:           30 * time.Minute,
			FlushInterval:      5 * time.Second,
			SlowQueryThreshold: 100 * time.Millisecond,
			IndexOptimization:  true,
		},
		Cache: &CacheConfig{
			L1Config: &L1Config{
				MaxSize:        10000,
				MaxMemory:      512 * 1024 * 1024,
				DefaultTTL:     5 * time.Minute,
				EvictionPolicy: "LRU",
			},
			L2Config: &L2Config{
				CacheDir:    "/tmp/typosentinel_cache",
				MaxSize:     100 * 1024 * 1024,
				DefaultTTL:  30 * time.Minute,
				Compression: true,
				Encryption:  false,
			},
			L3Config: &L3Config{
				Enabled:    true,
				RedisURL:   "redis://localhost:6379",
				DefaultTTL: 2 * time.Hour,
				MaxRetries: 3,
				RetryDelay: 1 * time.Second,
			},
			Warming: &WarmingConfig{
				Enabled:         true,
				WarmingInterval: 1 * time.Hour,
				MaxConcurrency:  5,
				PredictiveMode:  false,
			},
			Analysis: &AnalysisConfig{
				Enabled:          true,
				AnalysisInterval: 5 * time.Minute,
				RetentionPeriod:  24 * time.Hour,
				Recommendations:  true,
			},
		},
		Concurrency: &ConcurrencyConfig{
			MaxWorkers:     10,
			WorkerPoolSize: 5,
			QueueSize:      1000,
			RateLimit:      100,
			BatchSize:      50,
			LoadBalancing:  true,
			Adaptive:       true,
		},
		Profiling: &ProfilingConfig{
			Enabled:             true,
			SamplingRate:        0.1,
			ProfileInterval:     1 * time.Minute,
			RetentionPeriod:     24 * time.Hour,
			BottleneckDetection: true,
		},
		Optimization: &OptimizationEngineConfig{
			Enabled:              true,
			AutoOptimize:         true,
			OptimizationInterval: 15 * time.Minute,
			SafetyMode:           true,
			RevertOnFailure:      true,
		},
		Monitoring: &MonitoringConfig{
			Enabled:            true,
			MonitoringInterval: 30 * time.Second,
			AlertThresholds: &ResourceThresholds{
				MaxCPUUsage:    80.0,
				MaxMemoryUsage: 1024 * 1024 * 1024,
				MaxGoroutines:  1000,
				MaxGCPause:     100 * time.Millisecond,
				MaxHeapSize:    2 * 1024 * 1024 * 1024,
			},
			MetricsRetention: 7 * 24 * time.Hour,
		},
	}

	// Create optimization manager with custom config
	optManager := &OptimizationManager{
		config: config,
		db:     db,
	}

	// Initialize performance optimizer with custom config
	optManager.performanceOptimizer = NewPerformanceOptimizer(config, db)

	ctx, cancel := context.WithCancel(context.Background())
	optManager.ctx = ctx
	optManager.cancel = cancel

	// Start optimization
	if err := optManager.Start(); err != nil {
		log.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Monitor optimization for a period
	monitorCtx, monitorCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer monitorCancel()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Perform some operations to generate metrics
				packages := []types.Package{
					{Name: "test-package-1", Version: "1.0.0", Registry: "npm"},
					{Name: "test-package-2", Version: "2.0.0", Registry: "npm"},
				}
				optManager.BatchOptimizedThreatLookup(packages)

				// Get and log current stats
				stats := optManager.GetOptimizationStats()
				if stats != nil {
					log.Printf("Current optimization score: %.2f", stats.Performance.OptimizationScore)
					log.Printf("Cache performance: L1=%.2f%%, L2=%.2f%%, Overall=%.2f%%",
						stats.Cache.L1HitRatio*100,
						stats.Cache.L2HitRatio*100,
						stats.Cache.OverallHitRatio*100)
					log.Printf("Resource usage: CPU=%.2f%%, Memory=%dMB, Goroutines=%d",
						stats.Resource.CPUUsage,
						stats.Resource.MemoryUsage/(1024*1024),
						stats.Resource.GoroutineCount)
				}

				// Check for recommendations
				report := optManager.GenerateOptimizationReport()
				if report != nil && len(report.Recommendations) > 0 {
					log.Printf("New optimization recommendations available: %d", len(report.Recommendations))
					for _, rec := range report.Recommendations {
						log.Printf("  - %s: %s (Priority: %s)", rec.Type, rec.Description, rec.Priority)
					}
				}

				// Check for alerts
				if report != nil && len(report.Alerts) > 0 {
					log.Printf("Active alerts: %d", len(report.Alerts))
					for _, alert := range report.Alerts {
						log.Printf("  - %s: %s (Severity: %s)", alert.Type, alert.Message, alert.Severity)
					}
				}

			case <-monitorCtx.Done():
				return
			}
		}
	}()

	// Wait for monitoring to complete
	<-monitorCtx.Done()

	// Generate final report
	finalReport := optManager.GenerateOptimizationReport()
	if finalReport != nil {
		log.Println("\n=== Final Optimization Report ===")
		log.Printf("Overall efficiency score: %.2f", finalReport.Stats.Overall.EfficiencyScore)
		log.Printf("Optimization level: %s", finalReport.Stats.Overall.OptimizationLevel)
		log.Printf("Total recommendations: %d", len(finalReport.Recommendations))
		log.Printf("Total alerts: %d", len(finalReport.Alerts))
		log.Printf("Detected bottlenecks: %d", len(finalReport.Bottlenecks))
		log.Printf("Applied improvements: %d", len(finalReport.Improvements))
	}
}

// ExampleHealthMonitoring demonstrates health monitoring and alerting
func ExampleHealthMonitoring() {
	// Initialize database
	dbConfig := &config.DatabaseConfig{
		Type: "sqlite",
		Database: ":memory:",
	}
	db, err := database.NewThreatDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager
	optManager, err := QuickOptimizationSetup(db)
	if err != nil {
		log.Fatalf("Failed to create optimization manager: %v", err)
	}

	// Start optimization
	if err := optManager.Start(); err != nil {
		log.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Perform health check
	health := optManager.OptimizationHealthCheck()
	log.Println("\n=== Optimization Health Check ===")
	for key, value := range health {
		log.Printf("%s: %s", key, value)
	}

	// Monitor health over time
	monitorCtx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			health := optManager.OptimizationHealthCheck()
			if health["status"] != "healthy" {
				log.Printf("ALERT: Optimization health degraded - Status: %s, Reason: %s",
					health["status"], health["reason"])
			} else {
				log.Printf("Health OK - Cache: %s, Memory: %s, Level: %s",
					health["cache_hit_ratio"],
					health["memory_usage"],
					health["optimization_level"])
			}

		case <-monitorCtx.Done():
			return
		}
	}
}

// ExampleConfigurationManagement demonstrates configuration management
func ExampleConfigurationManagement() {
	// Initialize database
	dbConfig := &config.DatabaseConfig{
		Type: "sqlite",
		Database: ":memory:",
	}
	db, err := database.NewThreatDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Start with development configuration
	optManager, err := DevelopmentOptimizationSetup(db)
	if err != nil {
		log.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		log.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Get current configuration
	currentConfig := optManager.GetConfiguration()
	log.Printf("Current cache L1 size: %d", currentConfig.Cache.L1Config.MaxSize)
	log.Printf("Current max workers: %d", currentConfig.Concurrency.MaxWorkers)

	// Update to production configuration
	prodConfig := ProductionOptimizationConfig()
	if err := optManager.UpdateConfiguration(prodConfig); err != nil {
		log.Printf("Failed to update configuration: %v", err)
	} else {
		log.Println("Successfully updated to production configuration")
	}

	// Verify configuration change
	updatedConfig := optManager.GetConfiguration()
	log.Printf("Updated cache L1 size: %d", updatedConfig.Cache.L1Config.MaxSize)
	log.Printf("Updated max workers: %d", updatedConfig.Concurrency.MaxWorkers)

	// Get system-optimized configuration
	recommendedConfig := GetRecommendedConfiguration()
	log.Printf("Recommended configuration for this system:")
	log.Printf("  Cache L1 size: %d", recommendedConfig.Cache.L1Config.MaxSize)
	log.Printf("  Max workers: %d", recommendedConfig.Concurrency.MaxWorkers)
	log.Printf("  Database connections: %d", recommendedConfig.Database.ConnectionPoolSize)
}

// GetRecommendedConfiguration returns a system-optimized configuration
func GetRecommendedConfiguration() *PerformanceConfig {
	return ProductionOptimizationConfig()
}

// ExamplePerformanceBenchmarking demonstrates performance benchmarking
func ExamplePerformanceBenchmarking() {
	// Initialize database
	dbConfig := &config.DatabaseConfig{
		Type: "sqlite",
		Database: ":memory:",
	}
	db, err := database.NewThreatDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Add some test data
	testThreats := []*database.ThreatRecord{
		{
			PackageName: "malicious-package-1",
			Registry:    "npm",
			ThreatType:  "malware",
			Severity:    "high",
			Confidence:  0.95,
			Description: "Test malicious package 1",
			Source:      "test",
		},
		{
			PackageName: "malicious-package-2",
			Registry:    "npm",
			ThreatType:  "typosquatting",
			Severity:    "medium",
			Confidence:  0.85,
			Description: "Test malicious package 2",
			Source:      "test",
		},
	}

	for _, threat := range testThreats {
		if err := db.AddThreat(threat); err != nil {
			log.Printf("Failed to add test threat: %v", err)
		}
	}

	// Test without optimization
	log.Println("\n=== Benchmarking without optimization ===")
	start := time.Now()
	for i := 0; i < 1000; i++ {
		db.GetThreat("malicious-package-1", "npm")
	}
	unoptimizedDuration := time.Since(start)
	log.Printf("1000 queries without optimization: %v", unoptimizedDuration)

	// Test with optimization
	log.Println("\n=== Benchmarking with optimization ===")
	optManager, err := QuickOptimizationSetup(db)
	if err != nil {
		log.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		log.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Warm up cache
	for i := 0; i < 10; i++ {
		optManager.OptimizedThreatLookup("malicious-package-1", "npm")
	}

	start = time.Now()
	for i := 0; i < 1000; i++ {
		optManager.OptimizedThreatLookup("malicious-package-1", "npm")
	}
	optimizedDuration := time.Since(start)
	log.Printf("1000 queries with optimization: %v", optimizedDuration)

	// Calculate improvement
	improvement := float64(unoptimizedDuration-optimizedDuration) / float64(unoptimizedDuration) * 100
	log.Printf("Performance improvement: %.2f%%", improvement)

	// Get final stats
	stats := optManager.GetOptimizationStats()
	if stats != nil {
		log.Printf("Cache hit ratio: %.2f%%", stats.Cache.OverallHitRatio*100)
		log.Printf("Average query time: %v", stats.Database.AvgQueryTime)
		log.Printf("Optimization score: %.2f", stats.Performance.OptimizationScore)
	}
}
