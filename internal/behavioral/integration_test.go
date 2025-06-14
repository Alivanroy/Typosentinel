package behavioral

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnhancedAnalyzerIntegration tests the integration between enhanced and basic analyzers
func TestEnhancedAnalyzerIntegration(t *testing.T) {
	// Create both analyzers
	basicAnalyzer, err := NewBehavioralAnalyzer(DefaultConfig())
	require.NoError(t, err)

	enhancedAnalyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "integration-test-package"
	ctx := context.Background()

	// Start monitoring with both analyzers
	err = basicAnalyzer.StartMonitoring(packageName)
	require.NoError(t, err)

	err = enhancedAnalyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Simulate some time passing
	time.Sleep(100 * time.Millisecond)

	// Stop monitoring and get results
	basicResult, err := basicAnalyzer.StopMonitoring(packageName)
	require.NoError(t, err)

	enhancedResult, err := enhancedAnalyzer.StopEnhancedMonitoring(packageName)
	require.NoError(t, err)

	// Verify both results are valid
	assert.NotNil(t, basicResult)
	assert.NotNil(t, enhancedResult)
	assert.Equal(t, packageName, basicResult.PackageName)
	assert.Equal(t, packageName, enhancedResult.PackageName)

	// Enhanced result should have additional fields
	assert.NotNil(t, enhancedResult.RiskAssessment)
	assert.NotNil(t, enhancedResult.IOCs)
	assert.NotNil(t, enhancedResult.MITREMapping)
	assert.NotNil(t, enhancedResult.Recommendations)
}

// TestConcurrentMonitoring tests monitoring multiple packages simultaneously
func TestConcurrentMonitoring(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	ctx := context.Background()
	packages := []string{"package1", "package2", "package3"}

	// Start monitoring all packages
	for _, pkg := range packages {
		err := analyzer.StartEnhancedMonitoring(ctx, pkg)
		require.NoError(t, err)
	}

	// Verify all monitors are active
	analyzer.mu.RLock()
	assert.Len(t, analyzer.monitors, len(packages))
	for _, pkg := range packages {
		_, exists := analyzer.monitors[pkg]
		assert.True(t, exists)
	}
	analyzer.mu.RUnlock()

	// Stop monitoring all packages
	for _, pkg := range packages {
		result, err := analyzer.StopEnhancedMonitoring(pkg)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, pkg, result.PackageName)
	}

	// Verify all monitors are removed
	analyzer.mu.RLock()
	assert.Len(t, analyzer.monitors, 0)
	analyzer.mu.RUnlock()
}

// TestRealTimeEventProcessing tests real-time event processing
func TestRealTimeEventProcessing(t *testing.T) {
	config := DefaultEnhancedConfig()
	config.AnalysisSettings.RealTimeAnalysis = true
	config.AnalysisSettings.RiskScoreThreshold = 0.8

	analyzer, err := NewEnhancedBehavioralAnalyzer(config)
	require.NoError(t, err)

	packageName := "realtime-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add high-risk events that should trigger real-time analysis
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	monitor.Events = append(monitor.Events, 
		EnhancedEvent{
			ID:          "critical-event-1",
			Timestamp:   time.Now(),
			Type:        "network",
			Severity:    "critical",
			Description: "Suspicious outbound connection",
			RiskScore:   0.95,
			Confidence:  0.9,
		},
		EnhancedEvent{
			ID:          "critical-event-2",
			Timestamp:   time.Now(),
			Type:        "file",
			Severity:    "critical",
			Description: "Unauthorized file access",
			RiskScore:   0.92,
			Confidence:  0.88,
		},
	)
	analyzer.mu.Unlock()

	// Trigger real-time analysis
	analyzer.mu.RLock()
	analyzer.performRealTimeAnalysis(monitor)
	analyzer.mu.RUnlock()

	// Verify metrics were updated
	analyzer.mu.RLock()
	assert.Equal(t, 2, monitor.metrics.TotalEvents)
	assert.Greater(t, monitor.metrics.AverageRiskScore, 0.9)
	analyzer.mu.RUnlock()

	// Stop monitoring
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 2, result.TotalEvents)
}

// TestAnomalyDetectionIntegration tests anomaly detection with real events
func TestAnomalyDetectionIntegration(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "anomaly-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add events that should trigger anomaly detection
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	// Add baseline events (normal behavior)
	for i := 0; i < 10; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("normal-event-%d", i),
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Minute),
			Type:        "network",
			Severity:    "low",
			Description: "Normal network activity",
			RiskScore:   0.1,
			Confidence:  0.8,
		})
	}

	// Add anomalous events
	monitor.Events = append(monitor.Events, 
		EnhancedEvent{
			ID:          "anomaly-event-1",
			Timestamp:   time.Now(),
			Type:        "network",
			Severity:    "critical",
			Description: "Unusual network pattern detected",
			RiskScore:   0.95,
			Confidence:  0.9,
		},
		EnhancedEvent{
			ID:          "anomaly-event-2",
			Timestamp:   time.Now(),
			Type:        "process",
			Severity:    "high",
			Description: "Privilege escalation attempt",
			RiskScore:   0.88,
			Confidence:  0.85,
		},
	)
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Should have detected anomalies
	assert.Greater(t, len(result.Anomalies), 0)
	assert.NotNil(t, result.RiskAssessment)
	assert.Greater(t, result.RiskAssessment.OverallRiskScore, 0.5)
}

// TestPatternMatchingIntegration tests pattern matching with real events
func TestPatternMatchingIntegration(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "pattern-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add events that should match known patterns
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	// Add events matching suspicious network pattern
	for i := 0; i < 5; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("network-event-%d", i),
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Second),
			Type:        "network",
			Category:    "connection",
			Severity:    "medium",
			Description: "Outbound connection to suspicious domain",
			RiskScore:   0.7,
			Confidence:  0.8,
			Metadata: map[string]interface{}{
				"destination": "suspicious-domain.com",
				"port":        443,
			},
		})
	}

	// Add events matching file manipulation pattern
	for i := 0; i < 3; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("file-event-%d", i),
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Second),
			Type:        "file",
			Category:    "modification",
			Severity:    "high",
			Description: "Suspicious file modification",
			RiskScore:   0.8,
			Confidence:  0.85,
			Metadata: map[string]interface{}{
				"file_path": "/etc/passwd",
				"operation": "write",
			},
		})
	}
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Should have matched patterns
	assert.Greater(t, len(result.PatternMatches), 0)
	assert.NotNil(t, result.RiskAssessment)

	// Check for specific pattern matches
	patternFound := false
	for _, match := range result.PatternMatches {
		if match.PatternName == "Suspicious Network Activity" || 
		   match.PatternName == "Suspicious File Operations" {
			patternFound = true
			break
		}
	}
	assert.True(t, patternFound, "Expected pattern matches not found")
}

// TestMLIntegrationPlaceholder tests ML integration (placeholder)
func TestMLIntegrationPlaceholder(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "ml-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add diverse events for ML analysis
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	eventTypes := []string{"network", "file", "process", "registry"}
	severities := []string{"low", "medium", "high", "critical"}
	
	for i := 0; i < 20; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("ml-event-%d", i),
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Second),
			Type:        eventTypes[i%len(eventTypes)],
			Severity:    severities[i%len(severities)],
			Description: fmt.Sprintf("ML test event %d", i),
			RiskScore:   float64(i%10) / 10.0,
			Confidence:  0.8,
		})
	}
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// ML predictions should be present (even if placeholder)
	assert.NotNil(t, result.MLPredictions)
	assert.NotNil(t, result.RiskAssessment)
	assert.Equal(t, 20, result.TotalEvents)
}

// TestThreatIntelIntegrationPlaceholder tests threat intelligence integration (placeholder)
func TestThreatIntelIntegrationPlaceholder(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "threat-intel-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add events with known malicious indicators
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	monitor.Events = append(monitor.Events, 
		EnhancedEvent{
			ID:          "threat-intel-event-1",
			Timestamp:   time.Now(),
			Type:        "network",
			Severity:    "critical",
			Description: "Connection to known malicious domain",
			RiskScore:   0.95,
			Confidence:  0.9,
			Metadata: map[string]interface{}{
				"destination": "malicious-domain.com",
				"ip":          "192.168.1.100",
			},
		},
		EnhancedEvent{
			ID:          "threat-intel-event-2",
			Timestamp:   time.Now(),
			Type:        "file",
			Severity:    "high",
			Description: "Known malware hash detected",
			RiskScore:   0.9,
			Confidence:  0.95,
			Metadata: map[string]interface{}{
				"file_hash": "d41d8cd98f00b204e9800998ecf8427e",
				"file_path": "/tmp/suspicious.exe",
			},
		},
	)
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Threat intelligence hits should be present (even if placeholder)
	assert.NotNil(t, result.ThreatIntelHits)
	assert.NotNil(t, result.IOCs)
	assert.NotNil(t, result.RiskAssessment)
	assert.Greater(t, result.RiskAssessment.OverallRiskScore, 0.8)
}

// TestPerformanceUnderLoad tests analyzer performance under load
func TestPerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "performance-test-package"
	ctx := context.Background()

	start := time.Now()
	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add many events to test performance
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	for i := 0; i < 1000; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("perf-event-%d", i),
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Millisecond),
			Type:        "network",
			Severity:    "medium",
			Description: fmt.Sprintf("Performance test event %d", i),
			RiskScore:   0.5,
			Confidence:  0.8,
		})
	}
	analyzer.mu.Unlock()

	// Stop monitoring and measure time
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1000, result.TotalEvents)

	// Analysis should complete within reasonable time (adjust threshold as needed)
	assert.Less(t, elapsed, 10*time.Second, "Analysis took too long: %v", elapsed)

	t.Logf("Performance test completed in %v for %d events", elapsed, result.TotalEvents)
}

// TestErrorHandling tests error handling in various scenarios
func TestErrorHandling(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	// Test stopping non-existent monitor
	result, err := analyzer.StopEnhancedMonitoring("non-existent-package")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no monitor found")

	// Test starting monitor with empty package name
	ctx := context.Background()
	err = analyzer.StartEnhancedMonitoring(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "package name cannot be empty")

	// Test starting monitor twice for same package
	packageName := "duplicate-test-package"
	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	assert.NoError(t, err)

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "monitor already exists")

	// Clean up
	_, err = analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
}

// TestConfigurationValidation tests configuration validation
func TestConfigurationValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *EnhancedConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false, // Should use default
		},
		{
			name: "valid config",
			config: &EnhancedConfig{
				Enabled: true,
				AnalysisSettings: AnalysisSettings{
					SamplingRate:     1.0,
					AnomalyThreshold: 0.8,
					PatternThreshold: 0.7,
				},
			},
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &EnhancedConfig{
				Enabled: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer, err := NewEnhancedBehavioralAnalyzer(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, analyzer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, analyzer)
			}
		})
	}
}

// TestAdvancedPatternMatching tests advanced pattern matching capabilities
func TestAdvancedPatternMatching(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "pattern-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add events that should trigger pattern matches
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	// Add suspicious network pattern
	for i := 0; i < 5; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("network-pattern-%d", i),
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Second),
			Type:        "network",
			Severity:    "high",
			Description: "Suspicious network connection",
			RiskScore:   0.8,
			Confidence:  0.9,
			Metadata: map[string]interface{}{
				"destination": fmt.Sprintf("suspicious-domain-%d.com", i),
				"port":        443,
			},
		})
	}

	// Add file system pattern
	for i := 0; i < 3; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("file-pattern-%d", i),
			Timestamp:   time.Now().Add(-time.Duration(i) * time.Second),
			Type:        "file",
			Severity:    "medium",
			Description: "Suspicious file access",
			RiskScore:   0.6,
			Confidence:  0.8,
			Metadata: map[string]interface{}{
				"file_path": fmt.Sprintf("/tmp/suspicious-%d.txt", i),
				"operation": "write",
			},
		})
	}
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Should have pattern matches
	assert.NotEmpty(t, result.PatternMatches)
	assert.Equal(t, 8, result.TotalEvents)
	assert.Greater(t, result.RiskAssessment.OverallRiskScore, 0.5)
}

// TestEventCorrelation tests event correlation capabilities
func TestEventCorrelation(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "correlation-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add correlated events (attack chain)
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	baseTime := time.Now()
	correlatedEvents := []EnhancedEvent{
		{
			ID:          "recon-1",
			Timestamp:   baseTime,
			Type:        "network",
			Severity:    "low",
			Description: "Port scanning activity",
			RiskScore:   0.3,
			Confidence:  0.7,
		},
		{
			ID:          "exploit-1",
			Timestamp:   baseTime.Add(30 * time.Second),
			Type:        "process",
			Severity:    "high",
			Description: "Suspicious process execution",
			RiskScore:   0.8,
			Confidence:  0.9,
		},
		{
			ID:          "persistence-1",
			Timestamp:   baseTime.Add(60 * time.Second),
			Type:        "file",
			Severity:    "high",
			Description: "Suspicious file modification",
			RiskScore:   0.7,
			Confidence:  0.8,
		},
		{
			ID:          "exfiltration-1",
			Timestamp:   baseTime.Add(90 * time.Second),
			Type:        "network",
			Severity:    "critical",
			Description: "Data exfiltration attempt",
			RiskScore:   0.9,
			Confidence:  0.95,
		},
	}

	monitor.Events = append(monitor.Events, correlatedEvents...)
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Should detect correlation and attack chain
	assert.NotNil(t, result.CorrelatedEvents)
	assert.NotNil(t, result.AttackChains)
	assert.Equal(t, 4, result.TotalEvents)
	assert.Greater(t, result.RiskAssessment.OverallRiskScore, 0.7)
}

// TestTimelineAnalysis tests timeline analysis functionality
func TestTimelineAnalysis(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "timeline-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add events with specific timeline
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	baseTime := time.Now().Add(-5 * time.Minute)
	for i := 0; i < 10; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:          fmt.Sprintf("timeline-event-%d", i),
			Timestamp:   baseTime.Add(time.Duration(i) * 30 * time.Second),
			Type:        "network",
			Severity:    "medium",
			Description: fmt.Sprintf("Timeline event %d", i),
			RiskScore:   float64(i) / 10.0,
			Confidence:  0.8,
		})
	}
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Should have timeline analysis
	assert.NotNil(t, result.TimelineAnalysis)
	assert.Equal(t, 10, result.TotalEvents)
	assert.NotZero(t, result.TimelineAnalysis.Duration)
}

// TestMITREMapping tests MITRE ATT&CK framework mapping
func TestMITREMapping(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "mitre-test-package"
	ctx := context.Background()

	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add events that map to MITRE techniques
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	
	mitreMappedEvents := []EnhancedEvent{
		{
			ID:          "mitre-recon",
			Timestamp:   time.Now(),
			Type:        "network",
			Severity:    "medium",
			Description: "Network reconnaissance",
			RiskScore:   0.6,
			Confidence:  0.8,
			Metadata: map[string]interface{}{
				"mitre_technique": "T1046", // Network Service Scanning
			},
		},
		{
			ID:          "mitre-execution",
			Timestamp:   time.Now(),
			Type:        "process",
			Severity:    "high",
			Description: "Command and scripting interpreter",
			RiskScore:   0.8,
			Confidence:  0.9,
			Metadata: map[string]interface{}{
				"mitre_technique": "T1059", // Command and Scripting Interpreter
			},
		},
		{
			ID:          "mitre-persistence",
			Timestamp:   time.Now(),
			Type:        "file",
			Severity:    "high",
			Description: "Boot or logon autostart execution",
			RiskScore:   0.7,
			Confidence:  0.85,
			Metadata: map[string]interface{}{
				"mitre_technique": "T1547", // Boot or Logon Autostart Execution
			},
		},
	}

	monitor.Events = append(monitor.Events, mitreMappedEvents...)
	analyzer.mu.Unlock()

	// Stop monitoring and analyze
	result, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Should have MITRE mappings
	assert.NotNil(t, result.MITREMapping)
	assert.Equal(t, 3, result.TotalEvents)
	assert.Greater(t, result.RiskAssessment.OverallRiskScore, 0.6)
}

// BenchmarkEnhancedAnalysis benchmarks the enhanced analysis process
func BenchmarkEnhancedAnalysis(b *testing.B) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	packageName := "benchmark-package"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := analyzer.StartEnhancedMonitoring(ctx, fmt.Sprintf("%s-%d", packageName, i))
		if err != nil {
			b.Fatal(err)
		}

		// Add some events
		analyzer.mu.Lock()
		monitor := analyzer.monitors[fmt.Sprintf("%s-%d", packageName, i)]
		for j := 0; j < 10; j++ {
			monitor.Events = append(monitor.Events, EnhancedEvent{
				ID:          fmt.Sprintf("bench-event-%d-%d", i, j),
				Timestamp:   time.Now(),
				Type:        "network",
				Severity:    "medium",
				Description: "Benchmark event",
				RiskScore:   0.5,
				Confidence:  0.8,
			})
		}
		analyzer.mu.Unlock()

		_, err = analyzer.StopEnhancedMonitoring(fmt.Sprintf("%s-%d", packageName, i))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRiskAssessment benchmarks risk assessment calculation
func BenchmarkRiskAssessment(b *testing.B) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	if err != nil {
		b.Fatal(err)
	}

	analysis := &EnhancedBehavioralAnalysis{
		PackageName: "benchmark-package",
		Anomalies: make([]EnhancedAnomaly, 10),
		PatternMatches: make([]EnhancedPatternMatch, 5),
		ThreatIntelHits: make([]ThreatIntelHit, 3),
		MLPredictions: make([]MLPrediction, 2),
	}

	// Initialize with sample data
	for i := range analysis.Anomalies {
		analysis.Anomalies[i] = EnhancedAnomaly{
			ID:           fmt.Sprintf("anomaly-%d", i),
			Severity:     "medium",
			Confidence:   0.8,
			AnomalyScore: 0.6,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.calculateRiskAssessment(analysis)
	}
}