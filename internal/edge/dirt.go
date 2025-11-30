// Package edge implements the DIRT (Dependency Impact Risk Traversal) algorithm
// with Asset Criticality scoring for business-aware risk assessment
package edge

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// AssetCriticality defines the business value of the target application/repository
type AssetCriticality string

const (
	CriticalityUnknown  AssetCriticality = "UNKNOWN"  // Not yet assessed
	CriticalityPublic   AssetCriticality = "PUBLIC"   // Marketing sites, blogs (low impact)
	CriticalityInternal AssetCriticality = "INTERNAL" // Admin tools, internal apps (medium impact)
	CriticalityCritical AssetCriticality = "CRITICAL" // Billing, Auth, Core Services (high impact)
)

// DIRTConfig holds configuration for the DIRT algorithm with business context
type DIRTConfig struct {
	// Business impact multipliers
	CriticalMultiplier float64 `yaml:"critical_multiplier" json:"critical_multiplier"` // e.g., 2.0
	InternalMultiplier float64 `yaml:"internal_multiplier" json:"internal_multiplier"` // e.g., 1.0
	PublicMultiplier   float64 `yaml:"public_multiplier" json:"public_multiplier"`     // e.g., 0.5

	// Technical analysis parameters
	MaxPropagationDepth       int     `yaml:"max_propagation_depth" json:"max_propagation_depth"`
	HighRiskThreshold         float64 `yaml:"high_risk_threshold" json:"high_risk_threshold"`
	EnableCascadeAnalysis     bool    `yaml:"enable_cascade_analysis" json:"enable_cascade_analysis"`
	EnableHiddenRiskDetection bool    `yaml:"enable_hidden_risk_detection" json:"enable_hidden_risk_detection"`
	CacheEnabled              bool    `yaml:"cache_enabled" json:"cache_enabled"`

	// Policy enforcement thresholds
	BlockThreshold  float64 `yaml:"block_threshold" json:"block_threshold"`   // Auto-block if risk >= this
	AlertThreshold  float64 `yaml:"alert_threshold" json:"alert_threshold"`   // Alert if risk >= this
	ReviewThreshold float64 `yaml:"review_threshold" json:"review_threshold"` // Manual review if risk >= this
}

// DIRTMetrics tracks DIRT algorithm performance
type DIRTMetrics struct {
	PackagesAnalyzed   int64         `json:"packages_analyzed"`
	DependenciesScored int64         `json:"dependencies_scored"`
	HighRiskDetected   int64         `json:"high_risk_detected"`
	ProcessingTime     time.Duration `json:"processing_time"`
	CacheHits          int64         `json:"cache_hits"`
	CacheMisses        int64         `json:"cache_misses"`
	LastUpdated        time.Time     `json:"last_updated"`
}

// BusinessRiskAssessment contains the business-aware risk analysis
type BusinessRiskAssessment struct {
	PackageName          string                 `json:"package_name"`
	TechnicalRisk        float64                `json:"technical_risk"` // 0.0 - 1.0
	BusinessRisk         float64                `json:"business_risk"`  // Technical * Criticality
	AssetCriticality     AssetCriticality       `json:"asset_criticality"`
	ImpactMultiplier     float64                `json:"impact_multiplier"`
	RiskLevel            string                 `json:"risk_level"`         // LOW/MEDIUM/HIGH/CRITICAL
	RecommendedAction    string                 `json:"recommended_action"` // ALLOW/REVIEW/ALERT/BLOCK
	DependencyDepth      int                    `json:"dependency_depth"`
	DirectDependency     bool                   `json:"direct_dependency"`
	VulnerabilityCount   int                    `json:"vulnerability_count"`
	TransitiveDependents int                    `json:"transitive_dependents"` // How many packages depend on this
	Justification        string                 `json:"justification"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// DIRTAlgorithm implements business-aware dependency impact analysis
type DIRTAlgorithm struct {
	config  *DIRTConfig
	metrics *DIRTMetrics
	cache   sync.Map // Thread-safe cache for risk assessments
	mu      sync.RWMutex
}

// DefaultDIRTConfig returns a production-ready DIRT configuration
func DefaultDIRTConfig() *DIRTConfig {
	return &DIRTConfig{
		// Business multipliers - adjust based on your organization's risk tolerance
		CriticalMultiplier: 2.0, // Critical assets: double the risk score
		InternalMultiplier: 1.0, // Internal assets: standard risk score
		PublicMultiplier:   0.5, // Public assets: half the risk score

		// Technical parameters
		MaxPropagationDepth:       10,
		HighRiskThreshold:         0.7,
		EnableCascadeAnalysis:     true,
		EnableHiddenRiskDetection: true,
		CacheEnabled:              true,

		// Policy thresholds
		BlockThreshold:  0.9, // Auto-block if business risk >= 0.9
		AlertThreshold:  0.7, // Alert security team if >= 0.7
		ReviewThreshold: 0.5, // Flag for manual review if >= 0.5
	}
}

// NewDIRTAlgorithm creates a new DIRT algorithm instance
func NewDIRTAlgorithm(config *DIRTConfig) *DIRTAlgorithm {
	if config == nil {
		config = DefaultDIRTConfig()
	}

	return &DIRTAlgorithm{
		config: config,
		metrics: &DIRTMetrics{
			LastUpdated: time.Now(),
		},
	}
}

// Name returns the algorithm name
func (d *DIRTAlgorithm) Name() string {
	return "DIRT"
}

// Tier returns the algorithm tier
func (d *DIRTAlgorithm) Tier() AlgorithmTier {
	return TierCore
}

// Description returns the algorithm description
func (d *DIRTAlgorithm) Description() string {
	return "Dependency Impact Risk Traversal with business-aware risk assessment"
}

// AnalyzeWithCriticality performs business-aware risk analysis
func (d *DIRTAlgorithm) AnalyzeWithCriticality(
	ctx context.Context,
	pkg *types.Package,
	criticality AssetCriticality,
) (*BusinessRiskAssessment, error) {
	startTime := time.Now()
	defer func() {
		d.metrics.ProcessingTime = time.Since(startTime)
		d.metrics.LastUpdated = time.Now()
	}()

	// Check cache first
	if d.config.CacheEnabled {
		cacheKey := fmt.Sprintf("%s:%s:%s", pkg.Name, pkg.Version, criticality)
		if cached, ok := d.cache.Load(cacheKey); ok {
			d.metrics.CacheHits++
			return cached.(*BusinessRiskAssessment), nil
		}
		d.metrics.CacheMisses++
	}

	// Step 1: Calculate technical risk (0.0 - 1.0)
	technicalRisk := d.calculateTechnicalRisk(ctx, pkg)

	// Step 2: Apply business context multiplier
	multiplier := d.getCriticalityMultiplier(criticality)
	businessRisk := math.Min(technicalRisk*multiplier, 1.0)

	// Step 3: Determine risk level and action
	riskLevel, action := d.determineRiskLevelAndAction(businessRisk)

	// Step 4: Build assessment
	assessment := &BusinessRiskAssessment{
		PackageName:          pkg.Name,
		TechnicalRisk:        technicalRisk,
		BusinessRisk:         businessRisk,
		AssetCriticality:     criticality,
		ImpactMultiplier:     multiplier,
		RiskLevel:            riskLevel,
		RecommendedAction:    action,
		DependencyDepth:      d.calculateDependencyDepth(pkg),
		DirectDependency:     d.isDirectDependency(pkg),
		VulnerabilityCount:   len(pkg.Threats),
		TransitiveDependents: d.countTransitiveDependents(pkg),
		Justification:        d.buildJustification(technicalRisk, businessRisk, criticality),
		Metadata:             make(map[string]interface{}),
	}

	// Cache the result
	if d.config.CacheEnabled {
		cacheKey := fmt.Sprintf("%s:%s:%s", pkg.Name, pkg.Version, criticality)
		d.cache.Store(cacheKey, assessment)
	}

	// Update metrics
	d.metrics.PackagesAnalyzed++
	d.metrics.DependenciesScored++
	if businessRisk >= d.config.HighRiskThreshold {
		d.metrics.HighRiskDetected++
	}

	return assessment, nil
}

// calculateTechnicalRisk computes the base technical risk score
func (d *DIRTAlgorithm) calculateTechnicalRisk(ctx context.Context, pkg *types.Package) float64 {
	var risk float64

	// Factor 1: Known vulnerabilities (40% weight)
	vulnScore := d.calculateVulnerabilityScore(pkg)
	risk += vulnScore * 0.4

	// Factor 2: Package age and maintenance (20% weight)
	maintenanceScore := d.calculateMaintenanceScore(pkg)
	risk += maintenanceScore * 0.2

	// Factor 3: Download/usage patterns (20% weight)
	usageScore := d.calculateUsageAnomalyScore(pkg)
	risk += usageScore * 0.2

	// Factor 4: Dependency depth and complexity (20% weight)
	complexityScore := d.calculateComplexityScore(pkg)
	risk += complexityScore * 0.2

	return math.Min(risk, 1.0)
}

// calculateVulnerabilityScore scores based on known CVEs
func (d *DIRTAlgorithm) calculateVulnerabilityScore(pkg *types.Package) float64 {
	if len(pkg.Threats) == 0 {
		return 0.0
	}

	// Weight by severity
	var score float64
	for _, threat := range pkg.Threats {
		switch threat.Severity.String() {
		case "critical":
			score += 1.0
		case "high":
			score += 0.7
		case "medium":
			score += 0.4
		case "low":
			score += 0.1
		}
	}

	// Normalize: 3+ critical threats = 1.0 risk
	return math.Min(score/3.0, 1.0)
}

// calculateMaintenanceScore scores based on package maintenance status
func (d *DIRTAlgorithm) calculateMaintenanceScore(pkg *types.Package) float64 {
	// Check if package has LastUpdated metadata
	if pkg.Metadata == nil || pkg.Metadata.LastUpdated == nil {
		return 0.3 // Default moderate risk for unknown maintenance status
	}

	lastUpdated := pkg.Metadata.LastUpdated
	daysSinceUpdate := time.Since(*lastUpdated).Hours() / 24

	// Packages not updated in 2+ years are high risk
	if daysSinceUpdate > 730 {
		return 0.8
	} else if daysSinceUpdate > 365 {
		return 0.5
	} else if daysSinceUpdate > 180 {
		return 0.3
	}

	return 0.1 // Recently maintained = low risk
}

// calculateUsageAnomalyScore detects suspicious usage patterns
func (d *DIRTAlgorithm) calculateUsageAnomalyScore(pkg *types.Package) float64 {
	// This would integrate with your existing anomaly detection
	// For now, return baseline based on download count
	if pkg.Metadata == nil {
		return 0.2
	}

	downloads := pkg.Metadata.Downloads

	// Very low downloads = higher risk of typosquat/malware
	if downloads < 100 {
		return 0.7
	} else if downloads < 1000 {
		return 0.4
	}

	return 0.1 // Popular packages are lower risk
}

// calculateComplexityScore scores dependency complexity
func (d *DIRTAlgorithm) calculateComplexityScore(pkg *types.Package) float64 {
	if pkg.Dependencies == nil {
		return 0.0
	}

	depCount := len(pkg.Dependencies)

	// More dependencies = higher attack surface
	if depCount > 50 {
		return 0.8
	} else if depCount > 20 {
		return 0.5
	} else if depCount > 10 {
		return 0.3
	}

	return 0.1
}

// getCriticalityMultiplier returns the business impact multiplier
func (d *DIRTAlgorithm) getCriticalityMultiplier(criticality AssetCriticality) float64 {
	switch criticality {
	case CriticalityCritical:
		return d.config.CriticalMultiplier // 2.0
	case CriticalityInternal:
		return d.config.InternalMultiplier // 1.0
	case CriticalityPublic:
		return d.config.PublicMultiplier // 0.5
	case CriticalityUnknown:
		return 1.0 // Default to internal multiplier
	default:
		return 1.0
	}
}

// determineRiskLevelAndAction maps business risk to actionable recommendations
func (d *DIRTAlgorithm) determineRiskLevelAndAction(businessRisk float64) (string, string) {
	switch {
	case businessRisk >= d.config.BlockThreshold:
		return "CRITICAL", "BLOCK"
	case businessRisk >= d.config.AlertThreshold:
		return "HIGH", "ALERT"
	case businessRisk >= d.config.ReviewThreshold:
		return "MEDIUM", "REVIEW"
	default:
		return "LOW", "ALLOW"
	}
}

// buildJustification creates a human-readable explanation
func (d *DIRTAlgorithm) buildJustification(technical, business float64, criticality AssetCriticality) string {
	return fmt.Sprintf(
		"Technical risk: %.2f, Business context: %s (%.1fx multiplier), Final risk: %.2f",
		technical,
		criticality,
		d.getCriticalityMultiplier(criticality),
		business,
	)
}

// Helper methods (simplified implementations)
func (d *DIRTAlgorithm) calculateDependencyDepth(pkg *types.Package) int {
	// Would traverse dependency tree to find depth
	if pkg.Dependencies == nil {
		return 0
	}
	return 1 // Simplified
}

func (d *DIRTAlgorithm) isDirectDependency(pkg *types.Package) bool {
	// Check if this package is in the root package.json/requirements.txt
	// For now, assume all analyzed packages are direct dependencies
	return true
}

func (d *DIRTAlgorithm) countTransitiveDependents(pkg *types.Package) int {
	// Count how many packages in the tree depend on this one
	// Important for blast radius assessment
	// For now, return a simplified count
	return len(pkg.Dependencies)
}

// Analyze implements the Algorithm interface for compatibility
func (d *DIRTAlgorithm) Analyze(ctx context.Context, packages []string) (*AlgorithmResult, error) {
	// Default to INTERNAL criticality if not specified
	// For full functionality, use AnalyzeWithCriticality directly

	results := &AlgorithmResult{
		Algorithm: d.Name(),
		Timestamp: time.Now(),
		Packages:  packages,
		Findings:  make([]Finding, 0),
		Metadata:  make(map[string]interface{}),
	}

	for _, pkgName := range packages {
		// Create a basic package structure
		pkg := &types.Package{
			Name:     pkgName,
			Version:  "latest",
			Registry: "npm", // Default
		}

		// Use INTERNAL criticality as default for CLI
		assessment, err := d.AnalyzeWithCriticality(ctx, pkg, CriticalityInternal)
		if err != nil {
			return nil, err
		}

		// Map assessment to findings
		if assessment.RiskLevel == "HIGH" || assessment.RiskLevel == "CRITICAL" {
			finding := Finding{
				ID:              fmt.Sprintf("dirt_risk_%s", pkgName),
				Package:         pkgName,
				Type:            "SUPPLY_CHAIN_RISK",
				Severity:        strings.ToLower(assessment.RiskLevel),
				Message:         fmt.Sprintf("High supply chain risk detected: %s (Score: %.2f)", assessment.Justification, assessment.BusinessRisk),
				Confidence:      1.0,
				DetectedAt:      time.Now(),
				DetectionMethod: "DIRT",
				Evidence: []Evidence{
					{
						Type:        "business_risk",
						Description: "Business risk assessment score",
						Value:       assessment.BusinessRisk,
						Score:       assessment.BusinessRisk,
					},
					{
						Type:        "technical_risk",
						Description: "Technical risk score",
						Value:       assessment.TechnicalRisk,
						Score:       assessment.TechnicalRisk,
					},
					{
						Type:        "recommendation",
						Description: "Recommended action",
					},
				},
			}
			results.Findings = append(results.Findings, finding)
		}

		results.Metadata[pkgName] = assessment
	}

	return results, nil
}

// Configure implements the Algorithm interface
func (d *DIRTAlgorithm) Configure(config map[string]interface{}) error {
	// Update configuration dynamically
	if cm, ok := config["critical_multiplier"].(float64); ok {
		d.config.CriticalMultiplier = cm
	}
	if im, ok := config["internal_multiplier"].(float64); ok {
		d.config.InternalMultiplier = im
	}
	if pm, ok := config["public_multiplier"].(float64); ok {
		d.config.PublicMultiplier = pm
	}
	return nil
}

// GetMetrics returns algorithm performance metrics
func (d *DIRTAlgorithm) GetMetrics() *AlgorithmMetrics {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return &AlgorithmMetrics{
		PackagesProcessed: int(d.metrics.PackagesAnalyzed),
		ThreatsDetected:   int(d.metrics.HighRiskDetected),
		ProcessingTime:    d.metrics.ProcessingTime,
		LastUpdated:       d.metrics.LastUpdated,
	}
}

// Reset resets algorithm metrics
func (d *DIRTAlgorithm) Reset() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.metrics = &DIRTMetrics{
		LastUpdated: time.Now(),
	}
	d.cache = sync.Map{}
	return nil
}
