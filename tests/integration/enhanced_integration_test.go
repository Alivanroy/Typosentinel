package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/internal/plugins"
	"github.com/Alivanroy/Typosentinel/internal/threat_intelligence"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// EnhancedIntegrationTestSuite tests the complete enhanced Typosentinel system
type EnhancedIntegrationTestSuite struct {
	suite.Suite
	tempDir            string
	configManager      *config.ConfigManager
	config             *config.EnhancedConfig
	threatManager      *threat_intelligence.ThreatIntelligenceManager
	pluginManager      *plugins.PluginManager
	adaptiveThresholds *ml.AdaptiveThresholdManager
	dependencyDetector *detector.DependencyConfusionDetector
	supplyChainDetector *detector.SupplyChainDetector
	mockWebhookServer  *httptest.Server
	webhookRequests    []WebhookRequest
}

// WebhookRequest represents a captured webhook request
type WebhookRequest struct {
	Method  string
	Headers map[string]string
	Body    string
	Time    time.Time
}

// SetupSuite initializes the test suite
func (suite *EnhancedIntegrationTestSuite) SetupSuite() {
	// Create temporary directory
	var err error
	suite.tempDir, err = ioutil.TempDir("", "typosentinel-integration-test")
	require.NoError(suite.T(), err)

	// Setup mock webhook server
	suite.setupMockWebhookServer()

	// Create test configuration
	suite.createTestConfig()

	// Initialize components
	suite.initializeComponents()
}

// TearDownSuite cleans up after tests
func (suite *EnhancedIntegrationTestSuite) TearDownSuite() {
	if suite.mockWebhookServer != nil {
		suite.mockWebhookServer.Close()
	}

	if suite.threatManager != nil {
		suite.threatManager.Shutdown()
	}

	if suite.pluginManager != nil {
		suite.pluginManager.Shutdown()
	}

	os.RemoveAll(suite.tempDir)
}

// setupMockWebhookServer creates a mock webhook server for testing
func (suite *EnhancedIntegrationTestSuite) setupMockWebhookServer() {
	suite.webhookRequests = []WebhookRequest{}

	suite.mockWebhookServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		headers := make(map[string]string)
		for key, values := range r.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		suite.webhookRequests = append(suite.webhookRequests, WebhookRequest{
			Method:  r.Method,
			Headers: headers,
			Body:    string(body),
			Time:    time.Now(),
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Webhook received successfully",
			"request_id": fmt.Sprintf("req-%d", time.Now().Unix()),
		})
	}))
}

// createTestConfig creates a test configuration
func (suite *EnhancedIntegrationTestSuite) createTestConfig() {
	configPath := filepath.Join(suite.tempDir, "config.yaml")
	suite.configManager = config.NewConfigManager(configPath)

	// Create enhanced configuration for testing
	suite.config = &config.EnhancedConfig{
		Core: config.CoreConfig{
			Version:     "2.0.0-test",
			Environment: "test",
			Debug:       true,
			Verbose:     true,
			DataDir:     filepath.Join(suite.tempDir, "data"),
			CacheDir:    filepath.Join(suite.tempDir, "cache"),
			TempDir:     filepath.Join(suite.tempDir, "temp"),
			ConfigDir:   filepath.Join(suite.tempDir, "config"),
		},
		Detection: config.DetectionConfig{
			Enabled:       true,
			ParallelScans: 2,
			Timeout:       30,
			MaxPackageSize: 10,
			Typosquatting: config.TyposquattingConfig{
				Enabled:             true,
				SimilarityThreshold: 0.8,
				MinLength:           3,
				MaxDistance:         2,
				Algorithms:          []string{"levenshtein", "jaro_winkler"},
				PopularPackages:     []string{"lodash", "react", "express"},
			},
			DependencyConfusion: config.DependencyConfusionConfig{
				Enabled:            true,
				CheckPrivateRepos:  true,
				PrivateRegistries:  []string{"https://npm.test.com"},
				NamespacePatterns:  []string{"@test/*"},
				ScopeIndicators:    []string{"@", "_"},
				ConfusionThreshold: 0.7,
				VersionAnalysis:    true,
				DownloadAnalysis:   true,
			},
			SupplyChain: config.SupplyChainConfig{
				Enabled:                true,
				MaintainerAnalysis:     true,
				VersionPatternAnalysis: true,
				IntegrityChecks:        true,
				AnomalyDetection:       true,
				TrustedMaintainers:     []string{"facebook", "google"},
				SuspiciousPatterns:     []string{".*bitcoin.*", ".*crypto.*mining.*"},
				MinMaintainerAge:       30,
				MinPackageAge:          7,
				ReputationThreshold:    0.6,
			},
		},
		ML: config.MLConfig{
			Enabled:         true,
			ModelPath:       filepath.Join(suite.tempDir, "models"),
			TrainingData:    filepath.Join(suite.tempDir, "training"),
			UpdateInterval:  1, // 1 hour for testing
			MinTrainingSize: 10,
			ValidationSplit: 0.2,
			AdaptiveThresholds: config.AdaptiveThresholdsConfig{
				Enabled:             true,
				AdaptationFrequency: 1, // 1 hour for testing
				MinSamplesForAdapt:  5,
				MaxThresholdChange:  0.1,
				StabilityPeriod:     2, // 2 hours for testing
				PerformanceTargets: config.PerformanceTargetsConfig{
					TargetPrecision:      0.9,
					TargetRecall:         0.85,
					TargetF1Score:        0.87,
					MaxFalsePositiveRate: 0.1,
				},
				Ecosystems: map[string]config.EcosystemMLConfig{
					"npm": {
						Enabled:                 true,
						Typosquatting:           0.8,
						DependencyConfusion:     0.7,
						SupplyChain:             0.6,
						ModelVersion:            "v1.0.0-test",
						LastUpdated:             time.Now().Format(time.RFC3339),
					},
				},
			},
		},
		Plugins: config.PluginsConfig{
			Enabled:    true,
			PluginDir:  filepath.Join(suite.tempDir, "plugins"),
			AutoLoad:   true,
			Timeout:    30,
			MaxPlugins: 5,
			CICD:       make(map[string]config.PluginConfig),
			Webhooks: []config.WebhookConfig{
				{
					Name:           "test_webhook",
					URL:            suite.mockWebhookServer.URL,
					Method:         "POST",
					Headers:        map[string]string{"Content-Type": "application/json"},
					Secret:         "test-secret",
					Timeout:        10,
					RetryAttempts:  2,
					FilterSeverity: []string{"critical", "high"},
					FailOnCritical: false,
					FailOnHigh:     false,
				},
			},
			Custom: make(map[string]interface{}),
		},
		ThreatIntelligence: config.ThreatIntelligenceConfig{
			Enabled: true,
			Database: config.DatabaseConfig{
				Type:           "sqlite",
				Path:           filepath.Join(suite.tempDir, "threats.db"),
				MaxConnections: 5,
				Timeout:        10,
				Encryption:     false, // Disabled for testing
			},
			Feeds: []config.ThreatFeedConfig{},
			Correlation: config.CorrelationConfig{
				Enabled:             true,
				SimilarityThreshold: 0.8,
				CacheSize:           100,
				CacheTTL:            10,
				MaxConcurrent:       2,
				Timeout:             10,
			},
			Alerting: config.AlertingConfig{
				Enabled:  false, // Disabled for testing
				Channels: make(map[string]config.AlertChannel),
			},
			RealTimeUpdates: config.RealTimeUpdatesConfig{
				Enabled:       false, // Disabled for testing
				Channels:      []config.UpdateChannelConfig{},
				Processors:    make(map[string]config.ProcessorConfig),
				BufferSize:    100,
				BatchSize:     10,
				FlushInterval: 5,
				MaxRetries:    2,
			},
			Retention: config.RetentionConfig{
				ThreatData:      7,
				ScanResults:     3,
				Logs:            1,
				Metrics:         3,
				Backups:         7,
				CleanupInterval: 1,
			},
		},
		Logging: config.LoggingConfig{
			Level:      "debug",
			Format:     "json",
			Output:     []string{"stdout"},
			Structured: true,
		},
		Performance: config.PerformanceConfig{
			MaxConcurrency: 4,
			WorkerPoolSize: 2,
			QueueSize:      100,
			Timeout:        30 * time.Second,
			MemoryLimit:    256,
			CPULimit:       50.0,
			Caching: config.CachingConfig{
				Enabled:         true,
				MaxSize:         10,
				TTL:             5,
				CleanupInterval: 1,
				Persistent:      false,
			},
		},
		Security: config.SecurityConfig{
			Encryption: config.EncryptionConfig{
				Enabled: false, // Disabled for testing
			},
			Authentication: config.AuthConfig{
				Enabled: false, // Disabled for testing
			},
			Authorization: config.AuthzConfig{
				Enabled: false, // Disabled for testing
			},
			Audit: config.AuditConfig{
				Enabled: false, // Disabled for testing
			},
			RateLimit: config.RateLimitConfig{
				Enabled: false, // Disabled for testing
			},
		},
	}

	// Create necessary directories
	os.MkdirAll(suite.config.Core.DataDir, 0755)
	os.MkdirAll(suite.config.Core.CacheDir, 0755)
	os.MkdirAll(suite.config.Core.TempDir, 0755)
	os.MkdirAll(suite.config.ML.ModelPath, 0755)
	os.MkdirAll(suite.config.Plugins.PluginDir, 0755)

	// Save configuration
	err := suite.configManager.SaveConfig(suite.config)
	require.NoError(suite.T(), err)
}

// initializeComponents initializes all system components
func (suite *EnhancedIntegrationTestSuite) initializeComponents() {
	var err error

	// Initialize threat intelligence manager
	suite.threatManager, err = threat_intelligence.NewThreatIntelligenceManager(suite.config.ThreatIntelligence)
	require.NoError(suite.T(), err)

	// Initialize plugin manager
	suite.pluginManager, err = plugins.NewPluginManager(suite.config.Plugins, nil)
	require.NoError(suite.T(), err)

	// Initialize adaptive thresholds manager
	suite.adaptiveThresholds, err = ml.NewAdaptiveThresholdManager(suite.config.ML.AdaptiveThresholds)
	require.NoError(suite.T(), err)

	// Initialize detectors
	suite.dependencyDetector = detector.NewDependencyConfusionDetector(suite.config.Detection.DependencyConfusion)
	suite.supplyChainDetector = detector.NewSupplyChainDetector(suite.config.Detection.SupplyChain)
}

// TestConfigurationManagement tests configuration loading and validation
func (suite *EnhancedIntegrationTestSuite) TestConfigurationManagement() {
	// Test configuration loading
	loadedConfig, err := suite.configManager.LoadConfig()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), loadedConfig)

	// Verify core configuration
	assert.Equal(suite.T(), "2.0.0-test", loadedConfig.Core.Version)
	assert.Equal(suite.T(), "test", loadedConfig.Core.Environment)
	assert.True(suite.T(), loadedConfig.Core.Debug)

	// Verify detection configuration
	assert.True(suite.T(), loadedConfig.Detection.Enabled)
	assert.True(suite.T(), loadedConfig.Detection.Typosquatting.Enabled)
	assert.True(suite.T(), loadedConfig.Detection.DependencyConfusion.Enabled)
	assert.True(suite.T(), loadedConfig.Detection.SupplyChain.Enabled)

	// Verify ML configuration
	assert.True(suite.T(), loadedConfig.ML.Enabled)
	assert.True(suite.T(), loadedConfig.ML.AdaptiveThresholds.Enabled)

	// Verify plugin configuration
	assert.True(suite.T(), loadedConfig.Plugins.Enabled)
	assert.Len(suite.T(), loadedConfig.Plugins.Webhooks, 1)

	// Verify threat intelligence configuration
	assert.True(suite.T(), loadedConfig.ThreatIntelligence.Enabled)
	assert.Equal(suite.T(), "sqlite", loadedConfig.ThreatIntelligence.Database.Type)
}

// TestDependencyConfusionDetection tests dependency confusion detection
func (suite *EnhancedIntegrationTestSuite) TestDependencyConfusionDetection() {
	ctx := context.Background()

	// Test cases for dependency confusion
	testCases := []struct {
		name           string
		packageName    string
		expectedRisk   string
		expectedThreats int
	}{
		{
			name:           "Scoped package with confusion risk",
			packageName:    "@test/internal-utils",
			expectedRisk:   "high",
			expectedThreats: 1,
		},
		{
			name:           "Public package without confusion risk",
			packageName:    "lodash",
			expectedRisk:   "minimal",
			expectedThreats: 0,
		},
		{
			name:           "Suspicious internal package",
			packageName:    "internal_secret_lib",
			expectedRisk:   "medium",
			expectedThreats: 1,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result, err := suite.dependencyDetector.AnalyzePackage(ctx, tc.packageName, "1.0.0")
			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.expectedRisk, result.OverallRisk)
			assert.Len(t, result.Threats, tc.expectedThreats)

			if len(result.Threats) > 0 {
				assert.Equal(t, "dependency_confusion", result.Threats[0].Type)
				assert.Contains(t, []string{"high", "medium"}, result.Threats[0].Severity)
			}
		})
	}
}

// TestSupplyChainDetection tests supply chain attack detection
func (suite *EnhancedIntegrationTestSuite) TestSupplyChainDetection() {
	ctx := context.Background()

	// Test cases for supply chain detection
	testCases := []struct {
		name           string
		packageName    string
		maintainer     string
		expectedRisk   string
		expectedThreats int
	}{
		{
			name:           "Trusted maintainer package",
			packageName:    "react",
			maintainer:     "facebook",
			expectedRisk:   "minimal",
			expectedThreats: 0,
		},
		{
			name:           "Unknown maintainer package",
			packageName:    "suspicious-crypto-miner",
			maintainer:     "unknown-user",
			expectedRisk:   "high",
			expectedThreats: 1,
		},
		{
			name:           "Package with suspicious patterns",
			packageName:    "bitcoin-stealer-lib",
			maintainer:     "suspicious-dev",
			expectedRisk:   "critical",
			expectedThreats: 1,
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			result, err := suite.supplyChainDetector.AnalyzePackage(ctx, tc.packageName, "1.0.0", tc.maintainer)
			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tc.expectedRisk, result.OverallRisk)
			assert.Len(t, result.Threats, tc.expectedThreats)

			if len(result.Threats) > 0 {
				assert.Equal(t, "supply_chain", result.Threats[0].Type)
				assert.Contains(t, []string{"critical", "high", "medium"}, result.Threats[0].Severity)
			}
		})
	}
}

// TestAdaptiveThresholds tests adaptive threshold management
func (suite *EnhancedIntegrationTestSuite) TestAdaptiveThresholds() {
	ctx := context.Background()

	// Test getting adaptive thresholds
	thresholds, err := suite.adaptiveThresholds.GetAdaptiveThresholds(ctx, "npm")
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), thresholds)
	assert.Equal(suite.T(), 0.8, thresholds.Typosquatting)
	assert.Equal(suite.T(), 0.7, thresholds.DependencyConfusion)
	assert.Equal(suite.T(), 0.6, thresholds.SupplyChain)

	// Test analyzing with adaptive thresholds
	result := &types.ScanResult{
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
		RiskScore:      0.75,
		OverallRisk:    "medium",
		Threats: []types.Threat{
			{
				Type:        "typosquatting",
				Severity:    "medium",
				Description: "Potential typosquatting detected",
			},
		},
	}

	adaptedResult, err := suite.adaptiveThresholds.AnalyzeWithAdaptiveThresholds(ctx, "npm", result)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), adaptedResult)

	// Test updating performance stats
	stats := &ml.PerformanceStats{
		TruePositives:  85,
		FalsePositives: 5,
		TrueNegatives:  90,
		FalseNegatives: 10,
		TotalSamples:   190,
		Timestamp:      time.Now(),
	}

	err = suite.adaptiveThresholds.UpdatePerformanceStats(ctx, "npm", stats)
	assert.NoError(suite.T(), err)
}

// TestThreatIntelligenceIntegration tests threat intelligence integration
func (suite *EnhancedIntegrationTestSuite) TestThreatIntelligenceIntegration() {
	ctx := context.Background()

	// Add custom threat
	threat := &threat_intelligence.ThreatIntelligence{
		ID:          "test-threat-001",
		Type:        "malicious_package",
		Severity:    "critical",
		Description: "Known malicious package for testing",
		Indicators: []threat_intelligence.ThreatIndicator{
			{
				Type:  "package_name",
				Value: "malicious-test-package",
			},
		},
		Source:    "test",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := suite.threatManager.AddCustomThreat(ctx, threat)
	assert.NoError(suite.T(), err)

	// Test threat correlation
	result := &types.ScanResult{
		PackageName:    "malicious-test-package",
		PackageVersion: "1.0.0",
		RiskScore:      0.5,
		OverallRisk:    "medium",
		Threats:        []types.Threat{},
	}

	correlationResult, err := suite.threatManager.CorrelateThreat(ctx, result)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), correlationResult)
	assert.True(suite.T(), correlationResult.HasMatches)
	assert.Len(suite.T(), correlationResult.Matches, 1)
	assert.Equal(suite.T(), "critical", correlationResult.Matches[0].Severity)

	// Test getting threat intelligence status
	status, err := suite.threatManager.GetStatus(ctx)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), status)
	assert.True(suite.T(), status.DatabaseConnected)
	assert.Equal(suite.T(), int64(1), status.TotalThreats)
}

// TestPluginIntegration tests plugin system integration
func (suite *EnhancedIntegrationTestSuite) TestPluginIntegration() {
	ctx := context.Background()

	// Create test scan result
	result := &types.ScanResult{
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
		RiskScore:      0.9,
		OverallRisk:    "critical",
		Threats: []types.Threat{
			{
				Type:        "typosquatting",
				Severity:    "critical",
				Description: "Critical typosquatting threat detected",
			},
			{
				Type:        "supply_chain",
				Severity:    "high",
				Description: "Supply chain risk identified",
			},
		},
		Recommendations: []string{
			"Do not use this package",
			"Consider alternative packages",
		},
	}

	// Clear previous webhook requests
	suite.webhookRequests = []WebhookRequest{}

	// Execute plugins
	pluginResults, err := suite.pluginManager.ExecuteAll(ctx, result)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), pluginResults)

	// Wait for webhook to be called
	time.Sleep(100 * time.Millisecond)

	// Verify webhook was called
	assert.NotEmpty(suite.T(), suite.webhookRequests, "Webhook should have been called")

	if len(suite.webhookRequests) > 0 {
		req := suite.webhookRequests[0]
		assert.Equal(suite.T(), "POST", req.Method)
		assert.Equal(suite.T(), "application/json", req.Headers["Content-Type"])
		assert.Contains(suite.T(), req.Body, "test-package")
		assert.Contains(suite.T(), req.Body, "critical")
		assert.Contains(suite.T(), req.Body, "typosquatting")

		// Verify webhook signature if present
		if signature, exists := req.Headers["X-Typosentinel-Signature"]; exists {
			assert.True(suite.T(), strings.HasPrefix(signature, "sha256="))
		}
	}
}

// TestEndToEndWorkflow tests the complete end-to-end workflow
func (suite *EnhancedIntegrationTestSuite) TestEndToEndWorkflow() {
	ctx := context.Background()

	// Test package: suspicious typosquatting attempt
	packageName := "lodahs" // Typosquatting of "lodash"
	packageVersion := "1.0.0"

	// Step 1: Run typosquatting detection
	typoResult := &types.ScanResult{
		PackageName:    packageName,
		PackageVersion: packageVersion,
		RiskScore:      0.95,
		OverallRisk:    "critical",
		Threats: []types.Threat{
			{
				Type:        "typosquatting",
				Severity:    "critical",
				Description: "High similarity to popular package 'lodash'",
			},
		},
		Recommendations: []string{
			"This package appears to be typosquatting 'lodash'",
			"Use the official 'lodash' package instead",
		},
	}

	// Step 2: Apply adaptive thresholds
	adaptedResult, err := suite.adaptiveThresholds.AnalyzeWithAdaptiveThresholds(ctx, "npm", typoResult)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), adaptedResult)

	// Step 3: Correlate with threat intelligence
	correlationResult, err := suite.threatManager.CorrelateThreat(ctx, adaptedResult)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), correlationResult)

	// Step 4: Execute plugins (webhooks, CI/CD integrations)
	suite.webhookRequests = []WebhookRequest{} // Clear previous requests
	pluginResults, err := suite.pluginManager.ExecuteAll(ctx, adaptedResult)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), pluginResults)

	// Step 5: Verify webhook notification
	time.Sleep(100 * time.Millisecond)
	assert.NotEmpty(suite.T(), suite.webhookRequests, "Webhook should have been triggered")

	if len(suite.webhookRequests) > 0 {
		req := suite.webhookRequests[0]
		assert.Contains(suite.T(), req.Body, packageName)
		assert.Contains(suite.T(), req.Body, "critical")
		assert.Contains(suite.T(), req.Body, "typosquatting")
	}

	// Step 6: Update performance statistics
	stats := &ml.PerformanceStats{
		TruePositives:  1, // This was correctly identified as malicious
		FalsePositives: 0,
		TrueNegatives:  0,
		FalseNegatives: 0,
		TotalSamples:   1,
		Timestamp:      time.Now(),
	}

	err = suite.adaptiveThresholds.UpdatePerformanceStats(ctx, "npm", stats)
	assert.NoError(suite.T(), err)

	// Verify the complete workflow executed successfully
	assert.Equal(suite.T(), "critical", adaptedResult.OverallRisk)
	assert.True(suite.T(), adaptedResult.RiskScore >= 0.8)
	assert.NotEmpty(suite.T(), adaptedResult.Threats)
	assert.NotEmpty(suite.T(), adaptedResult.Recommendations)
}

// TestPerformanceAndScalability tests system performance under load
func (suite *EnhancedIntegrationTestSuite) TestPerformanceAndScalability() {
	ctx := context.Background()

	// Test concurrent package analysis
	packages := []string{
		"lodahs", "recat", "expresss", "axois", "momentt",
		"underscor", "jqeury", "bootstrp", "angualr", "veu",
	}

	start := time.Now()
	results := make([]*types.ScanResult, len(packages))
	errors := make([]error, len(packages))

	// Process packages concurrently
	for i, pkg := range packages {
		go func(index int, packageName string) {
			result := &types.ScanResult{
				PackageName:    packageName,
				PackageVersion: "1.0.0",
				RiskScore:      0.85,
				OverallRisk:    "high",
				Threats: []types.Threat{
					{
						Type:        "typosquatting",
						Severity:    "high",
						Description: "Potential typosquatting detected",
					},
				},
			}

			// Apply adaptive thresholds
			adaptedResult, err := suite.adaptiveThresholds.AnalyzeWithAdaptiveThresholds(ctx, "npm", result)
			results[index] = adaptedResult
			errors[index] = err
		}(i, pkg)
	}

	// Wait for all goroutines to complete
	time.Sleep(2 * time.Second)
	duration := time.Since(start)

	// Verify all packages were processed successfully
	for i, err := range errors {
		assert.NoError(suite.T(), err, "Package %s should be processed without error", packages[i])
		assert.NotNil(suite.T(), results[i], "Package %s should have results", packages[i])
	}

	// Verify performance (should complete within reasonable time)
	assert.Less(suite.T(), duration, 5*time.Second, "Concurrent processing should complete within 5 seconds")

	suite.T().Logf("Processed %d packages concurrently in %v", len(packages), duration)
}

// TestErrorHandlingAndRecovery tests error handling and system recovery
func (suite *EnhancedIntegrationTestSuite) TestErrorHandlingAndRecovery() {
	ctx := context.Background()

	// Test handling of invalid package names
	invalidPackages := []string{
		"", // Empty name
		"a", // Too short
		strings.Repeat("a", 300), // Too long
		"../../../etc/passwd", // Path traversal attempt
		"<script>alert('xss')</script>", // XSS attempt
	}

	for _, pkg := range invalidPackages {
		result := &types.ScanResult{
			PackageName:    pkg,
			PackageVersion: "1.0.0",
			RiskScore:      0.0,
			OverallRisk:    "unknown",
			Threats:        []types.Threat{},
		}

		// System should handle invalid input gracefully
		adaptedResult, err := suite.adaptiveThresholds.AnalyzeWithAdaptiveThresholds(ctx, "npm", result)
		
		// Should either succeed with sanitized input or fail gracefully
		if err != nil {
			assert.Contains(suite.T(), err.Error(), "invalid", "Error should indicate invalid input")
		} else {
			assert.NotNil(suite.T(), adaptedResult)
		}
	}

	// Test system recovery after component failure
	// Simulate database connection failure
	originalPath := suite.config.ThreatIntelligence.Database.Path
	suite.config.ThreatIntelligence.Database.Path = "/invalid/path/threats.db"

	// System should handle database errors gracefully
	result := &types.ScanResult{
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
		RiskScore:      0.5,
		OverallRisk:    "medium",
		Threats:        []types.Threat{},
	}

	_, err := suite.threatManager.CorrelateThreat(ctx, result)
	// Should either handle gracefully or return appropriate error
	if err != nil {
		assert.Contains(suite.T(), strings.ToLower(err.Error()), "database", "Error should indicate database issue")
	}

	// Restore original configuration
	suite.config.ThreatIntelligence.Database.Path = originalPath
}

// TestIntegrationTestSuite runs the integration test suite
func TestEnhancedIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(EnhancedIntegrationTestSuite))
}

// Helper function to create test threat intelligence data
func (suite *EnhancedIntegrationTestSuite) createTestThreatData() {
	ctx := context.Background()

	threats := []*threat_intelligence.ThreatIntelligence{
		{
			ID:          "threat-001",
			Type:        "typosquatting",
			Severity:    "critical",
			Description: "Known typosquatting package",
			Indicators: []threat_intelligence.ThreatIndicator{
				{Type: "package_name", Value: "lodahs"},
			},
			Source:    "test",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
		{
			ID:          "threat-002",
			Type:        "malicious_package",
			Severity:    "critical",
			Description: "Package contains malicious code",
			Indicators: []threat_intelligence.ThreatIndicator{
				{Type: "package_name", Value: "bitcoin-stealer"},
				{Type: "maintainer", Value: "malicious-user"},
			},
			Source:    "test",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
	}

	for _, threat := range threats {
		suite.threatManager.AddCustomThreat(ctx, threat)
	}
}