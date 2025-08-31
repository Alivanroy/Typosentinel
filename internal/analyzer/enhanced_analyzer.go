package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/sirupsen/logrus"
)

// EnhancedAnalyzer provides comprehensive security analysis with advanced threat detection
type EnhancedAnalyzer struct {
	baseAnalyzer        *Analyzer
	securityCoordinator *security.SecurityCoordinator
	config              *config.Config
	logger              logger.Logger
}

// EnhancedScanOptions extends ScanOptions with advanced security features
type EnhancedScanOptions struct {
	*ScanOptions
	EnableTemporalDetection     bool `json:"enable_temporal_detection"`
	EnableComplexityAnalysis    bool `json:"enable_complexity_analysis"`
	EnableTrustValidation       bool `json:"enable_trust_validation"`
	EnableMLHardening           bool `json:"enable_ml_hardening"`
	EnableMultiVectorDetection  bool `json:"enable_multi_vector_detection"`
	EnableBehavioralAnalysis    bool `json:"enable_behavioral_analysis"`
	EnableThreatIntelligence    bool `json:"enable_threat_intelligence"`
	EnableResponseOrchestration bool `json:"enable_response_orchestration"`
	EnableSecurityMetrics       bool `json:"enable_security_metrics"`
	EnableAlertManagement       bool `json:"enable_alert_management"`
}

// EnhancedScanResult extends ScanResult with comprehensive security analysis
type EnhancedScanResult struct {
	*ScanResult
	SecurityAnalysis        *security.ComprehensiveSecurityResult `json:"security_analysis"`
	AdvancedThreats         []security.DetectedThreat             `json:"advanced_threats"`
	SecurityRecommendations []security.SecurityRecommendation     `json:"security_recommendations"`
	SecurityAlerts          []security.SecurityAlert              `json:"security_alerts"`
	SecurityMetrics         *security.SecurityMetricsResult       `json:"security_metrics"`
	EnhancedSummary         *EnhancedScanSummary                  `json:"enhanced_summary"`
}

// EnhancedScanSummary provides comprehensive scan summary
type EnhancedScanSummary struct {
	*ScanSummary
	OverallThreatScore      float64 `json:"overall_threat_score"`
	ThreatLevel             string  `json:"threat_level"`
	TemporalThreats         int     `json:"temporal_threats"`
	ComplexityThreats       int     `json:"complexity_threats"`
	TrustIssues             int     `json:"trust_issues"`
	MLVulnerabilities       int     `json:"ml_vulnerabilities"`
	MultiVectorAttacks      int     `json:"multi_vector_attacks"`
	BehavioralAnomalies     int     `json:"behavioral_anomalies"`
	ThreatIntelMatches      int     `json:"threat_intel_matches"`
	SecurityAlertsGenerated int     `json:"security_alerts_generated"`
	RequiresImmediateAction bool    `json:"requires_immediate_action"`
}

// NewEnhancedAnalyzer creates a new enhanced analyzer
func NewEnhancedAnalyzer(cfg *config.Config, logger logger.Logger) (*EnhancedAnalyzer, error) {
	// Create base analyzer
	baseAnalyzer, err := New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create base analyzer: %w", err)
	}

	// Create security coordinator configuration
	securityConfig := &security.SecurityCoordinatorConfig{
		EnableTemporalDetection:     true,
		EnableComplexityAnalysis:    true,
		EnableTrustValidation:       true,
		EnableMLHardening:           true,
		EnableMultiVectorDetection:  true,
		EnableBehavioralAnalysis:    true,
		EnableThreatIntelligence:    true,
		EnableResponseOrchestration: false, // Disabled by default for safety
		EnableSecurityMetrics:       true,
		EnableAlertManagement:       true,
		MaxConcurrentScans:          10,
		ScanTimeout:                 30 * time.Minute,
		ThreatScoreThreshold:        0.7,
		CriticalThreatThreshold:     0.9,
		AutoResponseEnabled:         false,
		Enabled:                     true,
	}

	// Create security coordinator
	securityCoordinator := security.NewSecurityCoordinator(securityConfig, logger)

	return &EnhancedAnalyzer{
		baseAnalyzer:        baseAnalyzer,
		securityCoordinator: securityCoordinator,
		config:              cfg,
		logger:              logger,
	}, nil
}

// EnhancedScan performs comprehensive security analysis
func (ea *EnhancedAnalyzer) EnhancedScan(path string, options *EnhancedScanOptions) (*EnhancedScanResult, error) {
	start := time.Now()
	scanID := generateScanID()

	logrus.Infof("Starting enhanced security scan %s for path: %s", scanID, path)

	// Perform base scan first
	baseScanResult, err := ea.baseAnalyzer.Scan(path, options.ScanOptions)
	if err != nil {
		return nil, fmt.Errorf("base scan failed: %w", err)
	}

	// Initialize enhanced result
	enhancedResult := &EnhancedScanResult{
		ScanResult:              baseScanResult,
		AdvancedThreats:         []security.DetectedThreat{},
		SecurityRecommendations: []security.SecurityRecommendation{},
		SecurityAlerts:          []security.SecurityAlert{},
	}

	// Perform comprehensive security analysis for each package
	ctx := context.Background()
	var allSecurityResults []*security.ComprehensiveSecurityResult

	// Convert dependencies to packages for security analysis
	packages := ea.convertDependenciesToPackages(baseScanResult)

	for _, pkg := range packages {
		securityResult, err := ea.securityCoordinator.PerformComprehensiveSecurityAnalysis(ctx, pkg)
		if err != nil {
			logrus.Warnf("Security analysis failed for package %s: %v", pkg.Name, err)
			continue
		}

		if securityResult != nil {
			allSecurityResults = append(allSecurityResults, securityResult)

			// Aggregate results
			enhancedResult.AdvancedThreats = append(enhancedResult.AdvancedThreats, securityResult.DetectedThreats...)
			enhancedResult.SecurityRecommendations = append(enhancedResult.SecurityRecommendations, securityResult.SecurityRecommendations...)
			enhancedResult.SecurityAlerts = append(enhancedResult.SecurityAlerts, securityResult.AlertsGenerated...)
		}
	}

	// Calculate enhanced summary
	enhancedResult.EnhancedSummary = ea.calculateEnhancedSummary(allSecurityResults, baseScanResult)

	// Update scan duration
	enhancedResult.Duration = time.Since(start)

	logrus.Infof("Enhanced scan %s completed in %v. Found %d advanced threats, %d security alerts",
		scanID, enhancedResult.Duration, len(enhancedResult.AdvancedThreats), len(enhancedResult.SecurityAlerts))

	return enhancedResult, nil
}

// convertDependenciesToPackages converts dependencies to packages for security analysis
func (ea *EnhancedAnalyzer) convertDependenciesToPackages(scanResult *ScanResult) []*types.Package {
	var packages []*types.Package

	// Extract package information from threats and dependencies
	packageMap := make(map[string]*types.Package)

	// Process threats to extract package information
	for _, threat := range scanResult.Threats {
		if threat.Package != "" {
			packageName := threat.Package
			if _, exists := packageMap[packageName]; !exists {
				packageMap[packageName] = &types.Package{
					Name:     threat.Package,
					Version:  threat.Version,
					Registry: threat.Registry,
				}
			}
		}
	}

	// Convert map to slice
	for _, pkg := range packageMap {
		packages = append(packages, pkg)
	}

	return packages
}

// calculateEnhancedSummary calculates enhanced scan summary
func (ea *EnhancedAnalyzer) calculateEnhancedSummary(securityResults []*security.ComprehensiveSecurityResult, baseScanResult *ScanResult) *EnhancedScanSummary {
	summary := &EnhancedScanSummary{
		ScanSummary: &baseScanResult.Summary,
	}

	var totalThreatScore float64
	var threatCount int
	var requiresImmediateAction bool

	for _, result := range securityResults {
		if result == nil {
			continue
		}

		// Aggregate threat scores
		totalThreatScore += result.OverallThreatScore
		threatCount++

		// Check for immediate action requirement
		if result.RequiresImmediateAction {
			requiresImmediateAction = true
		}

		// Count specific threat types
		for _, threat := range result.DetectedThreats {
			switch threat.ThreatCategory {
			case "Temporal":
				summary.TemporalThreats++
			case "Complexity":
				summary.ComplexityThreats++
			case "Trust":
				summary.TrustIssues++
			case "ML":
				summary.MLVulnerabilities++
			case "MultiVector":
				summary.MultiVectorAttacks++
			case "Behavioral":
				summary.BehavioralAnomalies++
			case "ThreatIntel":
				summary.ThreatIntelMatches++
			}
		}

		// Count security alerts
		summary.SecurityAlertsGenerated += len(result.AlertsGenerated)
	}

	// Calculate overall threat score
	if threatCount > 0 {
		summary.OverallThreatScore = totalThreatScore / float64(threatCount)
	}

	// Determine threat level
	summary.ThreatLevel = ea.determineThreatLevel(summary.OverallThreatScore)
	summary.RequiresImmediateAction = requiresImmediateAction

	return summary
}

// determineThreatLevel determines threat level based on score
func (ea *EnhancedAnalyzer) determineThreatLevel(score float64) string {
	if score >= 0.9 {
		return "CRITICAL"
	} else if score >= 0.7 {
		return "HIGH"
	} else if score >= 0.5 {
		return "MEDIUM"
	} else if score >= 0.3 {
		return "LOW"
	}
	return "MINIMAL"
}

// DefaultEnhancedScanOptions returns default enhanced scan options
func DefaultEnhancedScanOptions() *EnhancedScanOptions {
	return &EnhancedScanOptions{
		ScanOptions: &ScanOptions{
			OutputFormat:           "json",
			DeepAnalysis:           true,
			IncludeDevDependencies: true,
			SimilarityThreshold:    0.8,
			CheckVulnerabilities:   true,
			AllowEmptyProjects:     false,
		},
		EnableTemporalDetection:     true,
		EnableComplexityAnalysis:    true,
		EnableTrustValidation:       true,
		EnableMLHardening:           true,
		EnableMultiVectorDetection:  true,
		EnableBehavioralAnalysis:    true,
		EnableThreatIntelligence:    true,
		EnableResponseOrchestration: false,
		EnableSecurityMetrics:       true,
		EnableAlertManagement:       true,
	}
}
