package optimization

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestOptimizationManagerBasic(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	// Test initial state
	if optManager.IsRunning() {
		t.Error("Optimization manager should not be running initially")
	}

	// Start optimization
	if err := optManager.Start(); err != nil {
		t.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Test running state
	if !optManager.IsRunning() {
		t.Error("Optimization manager should be running after start")
	}

	// Test health check
	health := optManager.OptimizationHealthCheck()
	if health["status"] != "healthy" {
		t.Errorf("Expected healthy status, got: %s", health["status"])
	}

	// Test configuration access
	config := optManager.GetConfiguration()
	if config == nil {
		t.Error("Configuration should not be nil")
	}

	// Test stats generation
	stats := optManager.GetOptimizationStats()
	if stats == nil {
		t.Error("Stats should not be nil when running")
	}

	// Test report generation
	report := optManager.GenerateOptimizationReport()
	if report == nil {
		t.Error("Report should not be nil when running")
	}

	// Stop optimization
	if err := optManager.Stop(); err != nil {
		t.Fatalf("Failed to stop optimization: %v", err)
	}

	// Test stopped state
	if optManager.IsRunning() {
		t.Error("Optimization manager should not be running after stop")
	}
}

func TestOptimizationManagerThreatLookup(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Add test threat
	testThreat := &database.ThreatRecord{
		PackageName: "test-malicious",
		Registry:    "npm",
		ThreatType:  "malware",
		Severity:    "high",
		Confidence:  0.95,
		Description: "Test malicious package",
		Source:      "test",
	}

	if err := db.AddThreat(testThreat); err != nil {
		t.Fatalf("Failed to add test threat: %v", err)
	}

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		t.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Test optimized threat lookup
	threat, err := optManager.OptimizedThreatLookup("test-malicious", "npm")
	if err != nil {
		t.Fatalf("Optimized threat lookup failed: %v", err)
	}

	if threat == nil {
		t.Error("Expected to find threat, got nil")
	} else {
		if threat.PackageName != "test-malicious" {
			t.Errorf("Expected package name 'test-malicious', got: %s", threat.PackageName)
		}
		if threat.ThreatType != "malware" {
			t.Errorf("Expected threat type 'malware', got: %s", threat.ThreatType)
		}
	}

	// Test lookup for non-existent threat
	threat, err = optManager.OptimizedThreatLookup("non-existent", "npm")
	if err != nil {
		t.Fatalf("Optimized threat lookup failed: %v", err)
	}

	if threat != nil {
		t.Error("Expected nil for non-existent threat, got result")
	}
}

func TestOptimizationManagerBatchLookup(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Add test threats
	testThreats := []*database.ThreatRecord{
		{
			PackageName: "malicious-1",
			Registry:    "npm",
			ThreatType:  "malware",
			Severity:    "high",
			Confidence:  0.95,
			Description: "Test malicious package 1",
			Source:      "test",
		},
		{
			PackageName: "malicious-2",
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
			t.Fatalf("Failed to add test threat: %v", err)
		}
	}

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		t.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Test batch lookup
	packages := []types.Package{
		{Name: "malicious-1", Version: "1.0.0", Registry: "npm"},
		{Name: "safe-package", Version: "2.0.0", Registry: "npm"},
		{Name: "malicious-2", Version: "1.5.0", Registry: "npm"},
		{Name: "another-safe", Version: "3.0.0", Registry: "npm"},
	}

	threats, err := optManager.BatchOptimizedThreatLookup(packages)
	if err != nil {
		t.Fatalf("Batch optimized threat lookup failed: %v", err)
	}

	if len(threats) != len(packages) {
		t.Errorf("Expected %d results, got %d", len(packages), len(threats))
	}

	// Check results
	foundThreats := 0
	for i, threat := range threats {
		if threat != nil {
			foundThreats++
			if packages[i].Name != threat.PackageName {
				t.Errorf("Mismatch at index %d: expected %s, got %s",
					i, packages[i].Name, threat.PackageName)
			}
		}
	}

	if foundThreats != 2 {
		t.Errorf("Expected to find 2 threats, found %d", foundThreats)
	}
}

func TestOptimizationManagerConfiguration(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		t.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Get initial configuration
	initialConfig := optManager.GetConfiguration()
	if initialConfig == nil {
		t.Fatal("Initial configuration should not be nil")
	}

	initialMaxWorkers := initialConfig.Concurrency.MaxWorkers

	// Create new configuration
	newConfig := TestOptimizationConfig()
	newConfig.Concurrency.MaxWorkers = initialMaxWorkers + 5

	// Update configuration
	if err := optManager.UpdateConfiguration(newConfig); err != nil {
		t.Fatalf("Failed to update configuration: %v", err)
	}

	// Verify configuration update
	updatedConfig := optManager.GetConfiguration()
	if updatedConfig.Concurrency.MaxWorkers != initialMaxWorkers+5 {
		t.Errorf("Expected max workers %d, got %d",
			initialMaxWorkers+5, updatedConfig.Concurrency.MaxWorkers)
	}

	// Test invalid configuration
	invalidConfig := &PerformanceConfig{}
	if err := optManager.UpdateConfiguration(invalidConfig); err == nil {
		t.Error("Expected error for invalid configuration, got nil")
	}
}

func TestOptimizationManagerStats(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	// Test stats when not running
	stats := optManager.GetOptimizationStats()
	if stats != nil {
		t.Error("Stats should be nil when not running")
	}

	if err := optManager.Start(); err != nil {
		t.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Test stats when running
	stats = optManager.GetOptimizationStats()
	if stats == nil {
		t.Fatal("Stats should not be nil when running")
	}

	// Verify stats structure
	if stats.Database == nil {
		t.Error("Database stats should not be nil")
	}
	if stats.Cache == nil {
		t.Error("Cache stats should not be nil")
	}
	if stats.Performance == nil {
		t.Error("Performance stats should not be nil")
	}
	if stats.Resource == nil {
		t.Error("Resource stats should not be nil")
	}
	if stats.Overall == nil {
		t.Error("Overall stats should not be nil")
	}

	// Verify timestamp
	if stats.Timestamp.IsZero() {
		t.Error("Stats timestamp should not be zero")
	}

	// Verify some basic values
	if stats.Cache.OverallHitRatio < 0 || stats.Cache.OverallHitRatio > 1 {
		t.Errorf("Invalid cache hit ratio: %f", stats.Cache.OverallHitRatio)
	}

	if stats.Performance.OptimizationScore < 0 || stats.Performance.OptimizationScore > 1 {
		t.Errorf("Invalid optimization score: %f", stats.Performance.OptimizationScore)
	}
}

func TestOptimizationManagerReport(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	// Test report when not running
	report := optManager.GenerateOptimizationReport()
	if report != nil {
		t.Error("Report should be nil when not running")
	}

	if err := optManager.Start(); err != nil {
		t.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Test report when running
	report = optManager.GenerateOptimizationReport()
	if report == nil {
		t.Fatal("Report should not be nil when running")
	}

	// Verify report structure
	if report.Stats == nil {
		t.Error("Report stats should not be nil")
	}
	if report.Recommendations == nil {
		t.Error("Report recommendations should not be nil")
	}
	if report.Alerts == nil {
		t.Error("Report alerts should not be nil")
	}
	if report.Bottlenecks == nil {
		t.Error("Report bottlenecks should not be nil")
	}
	if report.Improvements == nil {
		t.Error("Report improvements should not be nil")
	}

	// Verify timestamp
	if report.GeneratedAt.IsZero() {
		t.Error("Report timestamp should not be zero")
	}
}

func TestOptimizationManagerConcurrency(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Add test threats
	for i := 0; i < 100; i++ {
		threat := &database.ThreatRecord{
			PackageName: fmt.Sprintf("malicious-%d", i),
			Registry:    "npm",
			ThreatType:  "malware",
			Severity:    "high",
			Confidence:  0.95,
			Description: fmt.Sprintf("Test malicious package %d", i),
			Source:      "test",
		}
		if err := db.AddThreat(threat); err != nil {
			t.Fatalf("Failed to add test threat: %v", err)
		}
	}

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		t.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Test concurrent lookups
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const numGoroutines = 10
	const lookupsPerGoroutine = 50

	resultChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < lookupsPerGoroutine; j++ {
				select {
				case <-ctx.Done():
					resultChan <- ctx.Err()
					return
				default:
					packageName := fmt.Sprintf("malicious-%d", j%100)
					_, err := optManager.OptimizedThreatLookup(packageName, "npm")
					if err != nil {
						resultChan <- err
						return
					}
				}
			}
			resultChan <- nil
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-resultChan:
			if err != nil {
				t.Errorf("Concurrent lookup failed: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("Test timed out")
		}
	}

	// Verify stats after concurrent operations
	stats := optManager.GetOptimizationStats()
	if stats == nil {
		t.Fatal("Stats should not be nil after concurrent operations")
	}

	// Cache should have some hits due to repeated lookups
	if stats.Cache.OverallHitRatio == 0 {
		t.Error("Expected some cache hits from concurrent operations")
	}
}

func TestOptimizationManagerLifecycle(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("Failed to create optimization manager: %v", err)
	}

	// Test multiple start/stop cycles
	for i := 0; i < 3; i++ {
		// Start
		if err := optManager.Start(); err != nil {
			t.Fatalf("Failed to start optimization (cycle %d): %v", i, err)
		}

		if !optManager.IsRunning() {
			t.Errorf("Optimization manager should be running (cycle %d)", i)
		}

		// Test double start (should fail)
		if err := optManager.Start(); err == nil {
			t.Errorf("Expected error on double start (cycle %d)", i)
		}

		// Perform some operations
		_, err := optManager.OptimizedThreatLookup("test-package", "npm")
		if err != nil {
			t.Errorf("Lookup failed during cycle %d: %v", i, err)
		}

		// Stop
		if err := optManager.Stop(); err != nil {
			t.Fatalf("Failed to stop optimization (cycle %d): %v", i, err)
		}

		if optManager.IsRunning() {
			t.Errorf("Optimization manager should not be running after stop (cycle %d)", i)
		}

		// Test double stop (should fail)
		if err := optManager.Stop(); err == nil {
			t.Errorf("Expected error on double stop (cycle %d)", i)
		}

		// Test operations when stopped (should fail)
		_, err = optManager.OptimizedThreatLookup("test-package", "npm")
		if err == nil {
			t.Errorf("Expected error when performing lookup while stopped (cycle %d)", i)
		}
	}
}

func TestQuickSetupFunctions(t *testing.T) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test QuickOptimizationSetup
	optManager, err := QuickOptimizationSetup(db)
	if err != nil {
		t.Fatalf("QuickOptimizationSetup failed: %v", err)
	}
	if optManager == nil {
		t.Fatal("QuickOptimizationSetup returned nil manager")
	}

	// Test DevelopmentOptimizationSetup
	devManager, err := DevelopmentOptimizationSetup(db)
	if err != nil {
		t.Fatalf("DevelopmentOptimizationSetup failed: %v", err)
	}
	if devManager == nil {
		t.Fatal("DevelopmentOptimizationSetup returned nil manager")
	}

	// Test TestOptimizationSetup
	testManager, err := TestOptimizationSetup(db)
	if err != nil {
		t.Fatalf("TestOptimizationSetup failed: %v", err)
	}
	if testManager == nil {
		t.Fatal("TestOptimizationSetup returned nil manager")
	}

	// Verify different configurations
	quickConfig := optManager.GetConfiguration()
	devConfig := devManager.GetConfiguration()
	testConfig := testManager.GetConfiguration()

	if quickConfig == nil || devConfig == nil || testConfig == nil {
		t.Fatal("One or more configurations are nil")
	}

	// Test configs should have smaller cache sizes for testing
	if testConfig.Cache.L1Config.MaxSize != quickConfig.Cache.L1Config.MaxSize {
		t.Error("Test config should have smaller cache size than production config")
	}
}

func BenchmarkOptimizedThreatLookup(b *testing.B) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		b.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Add test threat
	testThreat := &database.ThreatRecord{
		PackageName: "benchmark-package",
		Registry:    "npm",
		ThreatType:  "malware",
		Severity:    "high",
		Confidence:  0.95,
		Description: "Benchmark test package",
		Source:      "test",
	}

	if err := db.AddThreat(testThreat); err != nil {
		b.Fatalf("Failed to add test threat: %v", err)
	}

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		b.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		b.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Warm up cache
	for i := 0; i < 10; i++ {
		optManager.OptimizedThreatLookup("benchmark-package", "npm")
	}

	b.ResetTimer()

	// Benchmark optimized lookups
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := optManager.OptimizedThreatLookup("benchmark-package", "npm")
			if err != nil {
				b.Errorf("Lookup failed: %v", err)
			}
		}
	})
}

func BenchmarkBatchOptimizedThreatLookup(b *testing.B) {
	// Create in-memory database
	db, err := database.NewThreatDB(":memory:")
	if err != nil {
		b.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Add test threats
	for i := 0; i < 100; i++ {
		threat := &database.ThreatRecord{
			PackageName: fmt.Sprintf("benchmark-package-%d", i),
			Registry:    "npm",
			ThreatType:  "malware",
			Severity:    "high",
			Confidence:  0.95,
			Description: fmt.Sprintf("Benchmark test package %d", i),
			Source:      "test",
		}
		if err := db.AddThreat(threat); err != nil {
			b.Fatalf("Failed to add test threat: %v", err)
		}
	}

	// Create optimization manager
	optManager, err := TestOptimizationSetup(db)
	if err != nil {
		b.Fatalf("Failed to create optimization manager: %v", err)
	}

	if err := optManager.Start(); err != nil {
		b.Fatalf("Failed to start optimization: %v", err)
	}
	defer optManager.Stop()

	// Prepare test packages
	packages := make([]types.Package, 10)
	for i := 0; i < 10; i++ {
		packages[i] = types.Package{
			Name:     fmt.Sprintf("benchmark-package-%d", i),
			Version:  "1.0.0",
			Registry: "npm",
		}
	}

	b.ResetTimer()

	// Benchmark batch lookups
	for i := 0; i < b.N; i++ {
		_, err := optManager.BatchOptimizedThreatLookup(packages)
		if err != nil {
			b.Errorf("Batch lookup failed: %v", err)
		}
	}
}