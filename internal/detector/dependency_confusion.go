package detector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Logger interface for dependency confusion detector
type Logger interface {
	Debug(msg string, args map[string]interface{})
	Info(msg string, args map[string]interface{})
	Warn(msg string, args map[string]interface{})
	Error(msg string, args map[string]interface{})
}

// DependencyConfusionDetector detects packages that exploit dependency confusion vulnerabilities
type DependencyConfusionDetector struct {
	config     *config.Config
	mlAnalyzer *ml.MLAnalyzer
	logger     Logger
}

// DependencyConfusionResult represents the result of dependency confusion analysis
type DependencyConfusionResult struct {
	IsConfusionRisk     bool                   `json:"is_confusion_risk"`
	ConfusionScore      float64                `json:"confusion_score"`
	NamespaceCollisions []NamespaceCollision   `json:"namespace_collisions"`
	ScopeAnalysis       ScopeAnalysis          `json:"scope_analysis"`
	Recommendations     []string               `json:"recommendations"`
	Details             map[string]interface{} `json:"details"`
}

// NamespaceCollision represents a potential namespace collision
type NamespaceCollision struct {
	PackageName     string  `json:"package_name"`
	CollisionType   string  `json:"collision_type"` // "exact", "similar", "typo"
	SimilarityScore float64 `json:"similarity_score"`
	Registry        string  `json:"registry"`
	IsInternal      bool    `json:"is_internal"`
}

// ScopeAnalysis represents the analysis of package scope (public vs private)
type ScopeAnalysis struct {
	IsPublicRegistry  bool     `json:"is_public_registry"`
	IsPrivateRegistry bool     `json:"is_private_registry"`
	RegistryType      string   `json:"registry_type"`
	ScopeIndicators   []string `json:"scope_indicators"`
	ConfidenceLevel   float64  `json:"confidence_level"`
}

// NewDependencyConfusionDetector creates a new dependency confusion detector
func NewDependencyConfusionDetector(config *config.Config, mlAnalyzer *ml.MLAnalyzer, logger Logger) *DependencyConfusionDetector {
	return &DependencyConfusionDetector{
		config:     config,
		mlAnalyzer: mlAnalyzer,
		logger:     logger,
	}
}

// Analyze performs dependency confusion analysis on a package
func (d *DependencyConfusionDetector) Analyze(ctx context.Context, pkg *types.Package) (*DependencyConfusionResult, error) {
	start := time.Now()
	d.logger.Debug("Starting dependency confusion analysis", map[string]interface{}{"package": pkg.Name})

	result := &DependencyConfusionResult{
		NamespaceCollisions: []NamespaceCollision{},
		Details:             make(map[string]interface{}),
	}

	// Analyze namespace collisions
	collisions, err := d.analyzeNamespaceCollisions(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("namespace collision analysis failed: %w", err)
	}
	result.NamespaceCollisions = collisions

	// Analyze package scope
	scopeAnalysis, err := d.analyzeScopeIndicators(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("scope analysis failed: %w", err)
	}
	result.ScopeAnalysis = *scopeAnalysis

	// Calculate confusion score
	confusionScore := d.calculateConfusionScore(collisions, scopeAnalysis)
	result.ConfusionScore = confusionScore

	// Determine if this is a confusion risk
	threshold := 0.7 // Default threshold
	if d.config.TypoDetection != nil && d.config.TypoDetection.Threshold > 0 {
		threshold = d.config.TypoDetection.Threshold
	}
	result.IsConfusionRisk = confusionScore >= threshold

	// Generate recommendations
	result.Recommendations = d.generateRecommendations(result)

	// Add analysis metadata
	result.Details["analysis_duration"] = time.Since(start).Milliseconds()
	result.Details["detector_version"] = "1.0.0"
	result.Details["threshold_used"] = threshold

	d.logger.Debug("Dependency confusion analysis completed", map[string]interface{}{
		"package":        pkg.Name,
		"confusion_score": confusionScore,
		"is_risk":        result.IsConfusionRisk,
		"duration":       time.Since(start),
	})

	return result, nil
}

// analyzeNamespaceCollisions detects potential namespace collisions
func (d *DependencyConfusionDetector) analyzeNamespaceCollisions(ctx context.Context, pkg *types.Package) ([]NamespaceCollision, error) {
	collisions := []NamespaceCollision{}

	// Check for exact matches in different registries
	exactMatches := d.findExactMatches(pkg.Name, pkg.Registry)
	for _, match := range exactMatches {
		collisions = append(collisions, NamespaceCollision{
			PackageName:     match.Name,
			CollisionType:   "exact",
			SimilarityScore: 1.0,
			Registry:        match.Registry,
			IsInternal:      false, // Default to false since Package type doesn't have IsInternal field
		})
	}

	// Check for similar package names that could cause confusion
	similarPackages := d.findSimilarPackages(pkg.Name, pkg.Registry)
	for _, similar := range similarPackages {
		similarity := d.calculateNameSimilarity(pkg.Name, similar.Name)
		if similarity >= 0.8 { // High similarity threshold
			collisions = append(collisions, NamespaceCollision{
				PackageName:     similar.Name,
				CollisionType:   "similar",
				SimilarityScore: similarity,
				Registry:        similar.Registry,
				IsInternal:      false, // Default to false since Package type doesn't have IsInternal field
			})
		}
	}

	// Check for potential typosquatting that could enable confusion attacks
	typoVariants := d.generateTypoVariants(pkg.Name)
	for _, variant := range typoVariants {
		if d.packageExists(variant, pkg.Registry) {
			similarity := d.calculateNameSimilarity(pkg.Name, variant)
			collisions = append(collisions, NamespaceCollision{
				PackageName:     variant,
				CollisionType:   "typo",
				SimilarityScore: similarity,
				Registry:        pkg.Registry,
				IsInternal:      false,
			})
		}
	}

	return collisions, nil
}

// analyzeScopeIndicators analyzes package scope indicators
func (d *DependencyConfusionDetector) analyzeScopeIndicators(ctx context.Context, pkg *types.Package) (*ScopeAnalysis, error) {
	analysis := &ScopeAnalysis{
		ScopeIndicators: []string{},
	}

	// Analyze registry type
	analysis.RegistryType = d.determineRegistryType(pkg.Registry)
	analysis.IsPublicRegistry = d.isPublicRegistry(pkg.Registry)
	analysis.IsPrivateRegistry = !analysis.IsPublicRegistry

	// Look for scope indicators in package name
	if strings.Contains(pkg.Name, "@") {
		analysis.ScopeIndicators = append(analysis.ScopeIndicators, "scoped_package")
	}

	if strings.Contains(pkg.Name, "-internal") || strings.Contains(pkg.Name, "_internal") {
		analysis.ScopeIndicators = append(analysis.ScopeIndicators, "internal_naming")
	}

	if strings.HasPrefix(pkg.Name, "company-") || strings.HasPrefix(pkg.Name, "org-") {
		analysis.ScopeIndicators = append(analysis.ScopeIndicators, "organizational_prefix")
	}

	// Calculate confidence level
	analysis.ConfidenceLevel = d.calculateScopeConfidence(analysis)

	return analysis, nil
}

// calculateConfusionScore calculates the overall confusion risk score
func (d *DependencyConfusionDetector) calculateConfusionScore(collisions []NamespaceCollision, scope *ScopeAnalysis) float64 {
	if len(collisions) == 0 {
		return 0.0
	}

	// Base score from highest collision similarity
	maxSimilarity := 0.0
	for _, collision := range collisions {
		if collision.SimilarityScore > maxSimilarity {
			maxSimilarity = collision.SimilarityScore
		}
	}

	score := maxSimilarity * 0.6 // 60% weight for similarity

	// Add weight for exact matches
	for _, collision := range collisions {
		if collision.CollisionType == "exact" {
			score += 0.3 // 30% additional weight for exact matches
			break
		}
	}

	// Add weight for scope analysis
	if scope.IsPublicRegistry && len(scope.ScopeIndicators) > 0 {
		score += 0.1 // 10% additional weight for scope indicators
	}

	// Ensure score doesn't exceed 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// generateRecommendations generates security recommendations
func (d *DependencyConfusionDetector) generateRecommendations(result *DependencyConfusionResult) []string {
	recommendations := []string{}

	if result.IsConfusionRisk {
		recommendations = append(recommendations, "HIGH RISK: This package may be exploiting dependency confusion vulnerabilities")
		recommendations = append(recommendations, "Verify the package source and maintainer authenticity")
		recommendations = append(recommendations, "Check if this package conflicts with internal dependencies")
		recommendations = append(recommendations, "Consider using package-lock files to prevent confusion attacks")
	}

	if len(result.NamespaceCollisions) > 0 {
		recommendations = append(recommendations, "Multiple packages with similar names detected")
		recommendations = append(recommendations, "Verify you're installing the correct package")
	}

	if result.ScopeAnalysis.IsPublicRegistry && len(result.ScopeAnalysis.ScopeIndicators) > 0 {
		recommendations = append(recommendations, "Package appears to target internal/organizational use but is on public registry")
	}

	return recommendations
}

// Helper methods (simplified implementations)
func (d *DependencyConfusionDetector) findExactMatches(name, registry string) []types.Package {
	// TODO: Implement database lookup for exact matches across registries
	return []types.Package{}
}

func (d *DependencyConfusionDetector) findSimilarPackages(name, registry string) []types.Package {
	// TODO: Implement fuzzy search for similar package names
	return []types.Package{}
}

func (d *DependencyConfusionDetector) generateTypoVariants(name string) []string {
	// TODO: Implement typo variant generation
	return []string{}
}

func (d *DependencyConfusionDetector) packageExists(name, registry string) bool {
	// TODO: Implement package existence check
	return false
}

func (d *DependencyConfusionDetector) calculateNameSimilarity(name1, name2 string) float64 {
	// TODO: Implement advanced string similarity calculation
	return 0.0
}

func (d *DependencyConfusionDetector) determineRegistryType(registry string) string {
	publicRegistries := map[string]bool{
		"npmjs.org":   true,
		"pypi.org":    true,
		"proxy.golang.org": true,
		"crates.io":   true,
	}

	if publicRegistries[registry] {
		return "public"
	}
	return "private"
}

func (d *DependencyConfusionDetector) isPublicRegistry(registry string) bool {
	return d.determineRegistryType(registry) == "public"
}

func (d *DependencyConfusionDetector) calculateScopeConfidence(analysis *ScopeAnalysis) float64 {
	confidence := 0.5 // Base confidence

	if analysis.IsPublicRegistry {
		confidence += 0.2
	}

	confidence += float64(len(analysis.ScopeIndicators)) * 0.1

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}