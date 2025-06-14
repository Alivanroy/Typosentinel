package behavioral

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnhancedBehavioralAnalyzer(t *testing.T) {
	tests := []struct {
		name     string
		config   *EnhancedConfig
		wantErr  bool
		errMsg   string
	}{
		{
			name:    "default config",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "valid config",
			config:  DefaultEnhancedConfig(),
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
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, analyzer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, analyzer)
				assert.NotNil(t, analyzer.config)
				assert.NotNil(t, analyzer.monitors)
				assert.NotNil(t, analyzer.anomalyDetector)
				assert.NotNil(t, analyzer.patternMatcher)
				assert.NotNil(t, analyzer.behaviorBaseline)
				assert.NotNil(t, analyzer.metrics)
			}
		})
	}
}

func TestDefaultEnhancedConfig(t *testing.T) {
	config := DefaultEnhancedConfig()

	assert.True(t, config.Enabled)
	assert.True(t, config.MonitoringModes.NetworkActivity)
	assert.True(t, config.MonitoringModes.FileSystemActivity)
	assert.True(t, config.MonitoringModes.ProcessActivity)
	assert.True(t, config.AnalysisSettings.DeepAnalysis)
	assert.True(t, config.AnalysisSettings.RealTimeAnalysis)
	assert.Equal(t, 1.0, config.AnalysisSettings.SamplingRate)
	assert.Equal(t, 0.7, config.AnalysisSettings.AnomalyThreshold)
	assert.Equal(t, 0.8, config.AnalysisSettings.PatternThreshold)
}

func TestStartEnhancedMonitoring(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	packageName := "test-package"
	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	assert.NoError(t, err)

	// Check that monitor was created
	analyzer.mu.RLock()
	monitor, exists := analyzer.monitors[packageName]
	analyzer.mu.RUnlock()

	assert.True(t, exists)
	assert.NotNil(t, monitor)
	assert.Equal(t, packageName, monitor.PackageName)
	assert.NotNil(t, monitor.metrics)
	assert.NotNil(t, monitor.behaviorProfile)
	assert.False(t, monitor.StartTime.IsZero())
}

func TestStopEnhancedMonitoring(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	packageName := "test-package"

	// Start monitoring first
	ctx := context.Background()
	err = analyzer.StartEnhancedMonitoring(ctx, packageName)
	require.NoError(t, err)

	// Add some test events
	analyzer.mu.Lock()
	monitor := analyzer.monitors[packageName]
	monitor.Events = append(monitor.Events, EnhancedEvent{
		ID:          "test-event-1",
		Timestamp:   time.Now(),
		Type:        "network",
		Category:    "connection",
		Severity:    "medium",
		Description: "Test network event",
		RiskScore:   0.5,
		Confidence:  0.8,
	})
	analyzer.mu.Unlock()

	// Stop monitoring
	analysis, err := analyzer.StopEnhancedMonitoring(packageName)
	assert.NoError(t, err)
	assert.NotNil(t, analysis)
	assert.Equal(t, packageName, analysis.PackageName)
	assert.Equal(t, 1, analysis.TotalEvents)
	assert.False(t, analysis.AnalysisTimestamp.IsZero())

	// Check that monitor was removed
	analyzer.mu.RLock()
	_, exists := analyzer.monitors[packageName]
	analyzer.mu.RUnlock()
	assert.False(t, exists)
}

func TestStopEnhancedMonitoringNonExistent(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	analysis, err := analyzer.StopEnhancedMonitoring("non-existent-package")
	assert.Error(t, err)
	assert.Nil(t, analysis)
	assert.Contains(t, err.Error(), "no monitor found")
}

func TestCalculateRiskAssessment(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	analysis := &EnhancedBehavioralAnalysis{
		PackageName: "test-package",
		Anomalies: []EnhancedAnomaly{
			{
				ID:           "anomaly-1",
				Type:         "behavioral",
				Severity:     "high",
				Confidence:   0.9,
				AnomalyScore: 0.8,
			},
		},
		PatternMatches: []EnhancedPatternMatch{
			{
				PatternID:   "pattern-1",
				PatternName: "Suspicious Network Activity",
				Severity:    "medium",
				Confidence:  0.7,
				MatchScore:  0.6,
			},
		},
		ThreatIntelHits: []ThreatIntelHit{
			{
				Indicator:  "malicious-domain.com",
				ThreatType: "malware",
				Confidence: 0.95,
			},
		},
		MLPredictions: []MLPrediction{
			{
				Prediction: "malicious",
				Confidence: 0.85,
			},
		},
	}

	riskAssessment := analyzer.calculateRiskAssessment(analysis)

	assert.NotNil(t, riskAssessment)
	assert.Greater(t, riskAssessment.OverallRiskScore, 0.0)
	assert.LessOrEqual(t, riskAssessment.OverallRiskScore, 1.0)
	assert.NotEmpty(t, riskAssessment.RiskLevel)
	assert.Greater(t, riskAssessment.Likelihood, 0.0)
	assert.Greater(t, riskAssessment.Impact, 0.0)
	assert.Greater(t, riskAssessment.ConfidenceLevel, 0.0)
	assert.NotEmpty(t, riskAssessment.RiskFactors)
}

func TestCalculateAnomalyRiskScore(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	tests := []struct {
		name      string
		anomalies []EnhancedAnomaly
		wantScore float64
	}{
		{
			name:      "no anomalies",
			anomalies: []EnhancedAnomaly{},
			wantScore: 0.0,
		},
		{
			name: "single high severity anomaly",
			anomalies: []EnhancedAnomaly{
				{
					Severity:     "high",
					Confidence:   0.9,
					AnomalyScore: 0.8,
				},
			},
			wantScore: 0.576, // 0.8 * 0.9 * 0.8 (high severity weight)
		},
		{
			name: "multiple anomalies",
			anomalies: []EnhancedAnomaly{
				{
					Severity:     "high",
					Confidence:   0.9,
					AnomalyScore: 0.8,
				},
				{
					Severity:     "medium",
					Confidence:   0.7,
					AnomalyScore: 0.6,
				},
			},
			wantScore: 0.414, // Average of weighted scores
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.calculateAnomalyRiskScore(tt.anomalies)
			assert.InDelta(t, tt.wantScore, score, 0.001)
		})
	}
}

func TestGetSeverityWeight(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	tests := []struct {
		severity string
		want     float64
	}{
		{"critical", 1.0},
		{"high", 0.8},
		{"medium", 0.6},
		{"low", 0.4},
		{"unknown", 0.2},
		{"CRITICAL", 1.0}, // Test case insensitivity
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			weight := analyzer.getSeverityWeight(tt.severity)
			assert.Equal(t, tt.want, weight)
		})
	}
}

func TestGetThreatTypeWeight(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	tests := []struct {
		threatType string
		want      float64
	}{
		{"malware", 1.0},
		{"ransomware", 1.0},
		{"trojan", 0.9},
		{"backdoor", 0.9},
		{"spyware", 0.8},
		{"adware", 0.4},
		{"suspicious", 0.6},
		{"unknown", 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.threatType, func(t *testing.T) {
			weight := analyzer.getThreatTypeWeight(tt.threatType)
			assert.Equal(t, tt.want, weight)
		})
	}
}

func TestGetRiskLevel(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	tests := []struct {
		score float64
		want  string
	}{
		{0.95, "critical"},
		{0.9, "critical"},
		{0.8, "high"},
		{0.7, "high"},
		{0.6, "medium"},
		{0.5, "medium"},
		{0.4, "low"},
		{0.3, "low"},
		{0.2, "minimal"},
		{0.0, "minimal"},
	}

	for _, tt := range tests {
		t.Run("score_"+fmt.Sprintf("%.2f", tt.score), func(t *testing.T) {
			level := analyzer.getRiskLevel(tt.score)
			assert.Equal(t, tt.want, level)
		})
	}
}

func TestGenerateEnhancedRecommendations(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	tests := []struct {
		name     string
		analysis *EnhancedBehavioralAnalysis
		wantMin  int // Minimum number of recommendations expected
	}{
		{
			name: "critical risk",
			analysis: &EnhancedBehavioralAnalysis{
				RiskAssessment: &RiskAssessment{
					OverallRiskScore: 0.95,
				},
			},
			wantMin: 4, // Should have immediate action recommendations
		},
		{
			name: "high risk with anomalies",
			analysis: &EnhancedBehavioralAnalysis{
				RiskAssessment: &RiskAssessment{
					OverallRiskScore: 0.8,
				},
				Anomalies: []EnhancedAnomaly{
					{ID: "anomaly-1"},
				},
			},
			wantMin: 3,
		},
		{
			name: "medium risk with patterns and threat intel",
			analysis: &EnhancedBehavioralAnalysis{
				RiskAssessment: &RiskAssessment{
					OverallRiskScore: 0.6,
				},
				PatternMatches: []EnhancedPatternMatch{
					{PatternID: "pattern-1"},
				},
				ThreatIntelHits: []ThreatIntelHit{
					{Indicator: "malicious.com"},
				},
			},
			wantMin: 5,
		},
		{
			name: "low risk",
			analysis: &EnhancedBehavioralAnalysis{
				RiskAssessment: &RiskAssessment{
					OverallRiskScore: 0.2,
				},
			},
			wantMin: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recommendations := analyzer.generateEnhancedRecommendations(tt.analysis)
			assert.GreaterOrEqual(t, len(recommendations), tt.wantMin)
			
			// Check that recommendations are not empty strings
			for _, rec := range recommendations {
				assert.NotEmpty(t, rec)
			}
		})
	}
}

func TestCalculateEventsPerSecond(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	monitor := &EnhancedMonitor{
		PackageName: "test-package",
		StartTime:   time.Now().Add(-2 * time.Minute),
		Events:      make([]EnhancedEvent, 0),
	}

	// Test with no events
	eps := analyzer.calculateEventsPerSecond(monitor)
	assert.Equal(t, 0.0, eps)

	// Add events within the last minute
	now := time.Now()
	for i := 0; i < 30; i++ {
		monitor.Events = append(monitor.Events, EnhancedEvent{
			ID:        fmt.Sprintf("event-%d", i),
			Timestamp: now.Add(-time.Duration(i) * time.Second),
		})
	}

	eps = analyzer.calculateEventsPerSecond(monitor)
	assert.Greater(t, eps, 0.0)
	assert.LessOrEqual(t, eps, 0.5) // 30 events in 60 seconds = 0.5 eps
}

func TestCalculateAverageRiskScore(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	monitor := &EnhancedMonitor{
		PackageName: "test-package",
		Events:      make([]EnhancedEvent, 0),
	}

	// Test with no events
	avgScore := analyzer.calculateAverageRiskScore(monitor)
	assert.Equal(t, 0.0, avgScore)

	// Add events with different risk scores
	monitor.Events = append(monitor.Events,
		EnhancedEvent{ID: "event-1", RiskScore: 0.8},
		EnhancedEvent{ID: "event-2", RiskScore: 0.6},
		EnhancedEvent{ID: "event-3", RiskScore: 0.4},
	)

	avgScore = analyzer.calculateAverageRiskScore(monitor)
	assert.InDelta(t, 0.6, avgScore, 0.001) // (0.8 + 0.6 + 0.4) / 3 = 0.6
}

func TestLoadAdvancedBehavioralPatterns(t *testing.T) {
	patterns := loadAdvancedBehavioralPatterns()

	assert.NotEmpty(t, patterns)
	assert.GreaterOrEqual(t, len(patterns), 5) // Should have at least 5 patterns

	// Check that all patterns have required fields
	for _, pattern := range patterns {
		assert.NotEmpty(t, pattern.ID)
		assert.NotEmpty(t, pattern.Name)
		assert.NotEmpty(t, pattern.Description)
		assert.NotEmpty(t, pattern.EventTypes)
		assert.NotEmpty(t, pattern.RiskLevel)
		assert.Greater(t, pattern.Confidence, 0.0)
		assert.LessOrEqual(t, pattern.Confidence, 1.0)
		assert.True(t, pattern.Enabled)
		assert.Greater(t, pattern.Threshold, 0)
		assert.Greater(t, pattern.TimeWindow, time.Duration(0))
	}

	// Check for specific patterns
	patternIDs := make(map[string]bool)
	for _, pattern := range patterns {
		patternIDs[pattern.ID] = true
	}

	expectedPatterns := []string{
		"net_suspicious_connections",
		"file_suspicious_operations",
		"proc_privilege_escalation",
		"crypto_weak_encryption",
		"data_exfiltration",
	}

	for _, expectedID := range expectedPatterns {
		assert.True(t, patternIDs[expectedID], "Expected pattern %s not found", expectedID)
	}
}

func TestEnhancedBehavioralAnalysisUtilityMethods(t *testing.T) {
	analysis := &EnhancedBehavioralAnalysis{
		PackageName: "test-package",
		RiskAssessment: &RiskAssessment{
			OverallRiskScore: 0.85,
		},
		Anomalies: []EnhancedAnomaly{
			{
				ID:           "anomaly-1",
				AnomalyScore: 0.9,
			},
			{
				ID:           "anomaly-2",
				AnomalyScore: 0.7,
			},
		},
		IOCs: []IOC{
			{
				Type:     "domain",
				Value:    "malicious.com",
				Severity: "critical",
			},
			{
				Type:     "ip",
				Value:    "192.168.1.100",
				Severity: "medium",
			},
		},
		MITREMapping: []MITREMapping{
			{
				TacticName:    "Initial Access",
				TechniqueName: "Spearphishing Link",
			},
			{
				TacticName:    "Execution",
				TechniqueName: "Command and Scripting Interpreter",
			},
		},
		ActionRequired: true,
	}

	// Test GetSeverityLevel
	severity := analysis.GetSeverityLevel()
	assert.Equal(t, "high", severity)

	// Test RequiresImmediateAction
	analysis.SeverityLevel = severity
	requiresAction := analysis.RequiresImmediateAction()
	assert.True(t, requiresAction)

	// Test GetHighestRiskAnomaly
	highestAnomaly := analysis.GetHighestRiskAnomaly()
	assert.NotNil(t, highestAnomaly)
	assert.Equal(t, "anomaly-1", highestAnomaly.ID)
	assert.Equal(t, 0.9, highestAnomaly.AnomalyScore)

	// Test GetCriticalIOCs
	criticalIOCs := analysis.GetCriticalIOCs()
	assert.Len(t, criticalIOCs, 1)
	assert.Equal(t, "malicious.com", criticalIOCs[0].Value)

	// Test GetMITRETactics
	tactics := analysis.GetMITRETactics()
	assert.Contains(t, tactics, "Execution")
	assert.Contains(t, tactics, "Initial Access")
	assert.Len(t, tactics, 2)

	// Test JSON serialization
	jsonData, err := analysis.ToJSON()
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Test JSON deserialization
	newAnalysis := &EnhancedBehavioralAnalysis{}
	err = newAnalysis.FromJSON(jsonData)
	assert.NoError(t, err)
	assert.Equal(t, analysis.PackageName, newAnalysis.PackageName)
	assert.Equal(t, analysis.RiskAssessment.OverallRiskScore, newAnalysis.RiskAssessment.OverallRiskScore)
}

func TestNewHelperInstances(t *testing.T) {
	// Test NewMonitorMetrics
	metrics := NewMonitorMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, 0, metrics.TotalEvents)
	assert.Equal(t, 0.0, metrics.EventsPerSecond)
	assert.Equal(t, 0.0, metrics.AverageRiskScore)

	// Test NewBehaviorProfile
	packageName := "test-package"
	profile := NewBehaviorProfile(packageName)
	assert.NotNil(t, profile)
	assert.Equal(t, packageName, profile.PackageName)
	assert.False(t, profile.Created.IsZero())
	assert.False(t, profile.LastUpdated.IsZero())
	assert.Equal(t, 0.5, profile.TrustScore)
	assert.Equal(t, 0.5, profile.ReputationScore)

	// Test NewBehaviorBaseline
	baseline := NewBehaviorBaseline()
	assert.NotNil(t, baseline)
	assert.False(t, baseline.Created.IsZero())
	assert.False(t, baseline.LastUpdated.IsZero())
	assert.Equal(t, 0.95, baseline.ConfidenceLevel)
	assert.NotNil(t, baseline.EventFrequencies)
	assert.NotNil(t, baseline.StatisticalMetrics)

	// Test NewBehaviorMetrics
	behaviorMetrics := NewBehaviorMetrics()
	assert.NotNil(t, behaviorMetrics)
	assert.Equal(t, int64(0), behaviorMetrics.TotalAnalyses)
	assert.Equal(t, int64(0), behaviorMetrics.AnomaliesDetected)
	assert.Equal(t, 0.0, behaviorMetrics.Accuracy)
	assert.False(t, behaviorMetrics.LastUpdated.IsZero())
}

func TestRealTimeAnalysis(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	monitor := &EnhancedMonitor{
		PackageName: "test-package",
		StartTime:   time.Now(),
		Events:      make([]EnhancedEvent, 0),
		metrics:     NewMonitorMetrics(),
	}

	// Add a high-risk event
	monitor.Events = append(monitor.Events, EnhancedEvent{
		ID:          "high-risk-event",
		Timestamp:   time.Now(),
		Type:        "network",
		Severity:    "critical",
		Description: "Suspicious network activity",
		RiskScore:   0.95, // Above critical threshold
		Confidence:  0.9,
	})

	// Perform real-time analysis
	analyzer.performRealTimeAnalysis(monitor)

	// Check that metrics were updated
	assert.Equal(t, 1, monitor.metrics.TotalEvents)
	assert.Equal(t, 0.95, monitor.metrics.AverageRiskScore)
}

func TestCompareSeverity(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	tests := []struct {
		s1       string
		s2       string
		expected int
	}{
		{"critical", "high", 1},
		{"high", "critical", -1},
		{"medium", "medium", 0},
		{"low", "minimal", 1},
		{"minimal", "critical", -4},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.s1, tt.s2), func(t *testing.T) {
			result := analyzer.compareSeverity(tt.s1, tt.s2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateTimeToRemediation(t *testing.T) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	require.NoError(t, err)

	tests := []struct {
		riskScore float64
		expected  time.Duration
	}{
		{0.95, time.Hour},
		{0.8, 4 * time.Hour},
		{0.6, 24 * time.Hour},
		{0.4, 7 * 24 * time.Hour},
		{0.1, 30 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("risk_%.2f", tt.riskScore), func(t *testing.T) {
			duration := analyzer.calculateTimeToRemediation(tt.riskScore)
			assert.Equal(t, tt.expected, duration)
		})
	}
}

// Benchmark tests
func BenchmarkNewEnhancedBehavioralAnalyzer(b *testing.B) {
	config := DefaultEnhancedConfig()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := NewEnhancedBehavioralAnalyzer(config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCalculateRiskAssessment(b *testing.B) {
	analyzer, err := NewEnhancedBehavioralAnalyzer(DefaultEnhancedConfig())
	if err != nil {
		b.Fatal(err)
	}

	analysis := &EnhancedBehavioralAnalysis{
		PackageName: "benchmark-package",
		Anomalies: []EnhancedAnomaly{
			{ID: "anomaly-1", Severity: "high", Confidence: 0.9, AnomalyScore: 0.8},
			{ID: "anomaly-2", Severity: "medium", Confidence: 0.7, AnomalyScore: 0.6},
		},
		PatternMatches: []EnhancedPatternMatch{
			{PatternID: "pattern-1", Severity: "high", Confidence: 0.8, MatchScore: 0.7},
		},
		ThreatIntelHits: []ThreatIntelHit{
			{Indicator: "malicious.com", ThreatType: "malware", Confidence: 0.95},
		},
		MLPredictions: []MLPrediction{
			{Prediction: "malicious", Confidence: 0.85},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.calculateRiskAssessment(analysis)
	}
}

func BenchmarkLoadAdvancedBehavioralPatterns(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = loadAdvancedBehavioralPatterns()
	}
}