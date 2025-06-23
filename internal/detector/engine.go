package detector

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Engine is the main detection engine that orchestrates various detection algorithms
type Engine struct {
	config                        *config.Config
	lexicalDetector               *LexicalDetector
	homoglyphDetector             *HomoglyphDetector
	reputationEngine              *ReputationEngine
	enhancedTyposquattingDetector *EnhancedTyposquattingDetector
	version                       string
}

// Options contains options for the detection engine
type Options struct {
	DeepAnalysis        bool
	SimilarityThreshold float64
}

// New creates a new detection engine
func New(cfg *config.Config) *Engine {
	return &Engine{
		config:                        cfg,
		lexicalDetector:               NewLexicalDetector(cfg),
		homoglyphDetector:             NewHomoglyphDetector(),
		reputationEngine:              NewReputationEngine(cfg),
		enhancedTyposquattingDetector: NewEnhancedTyposquattingDetector(),
		version:                       "1.0.0",
	}
}

// Version returns the detector engine version
func (e *Engine) Version() string {
	return e.version
}

// CheckPackageResult represents the result of a single package check
type CheckPackageResult struct {
	Package        string                 `json:"package"`
	Registry       string                 `json:"registry"`
	ThreatLevel    string                 `json:"threat_level"`
	Confidence     float64                `json:"confidence"`
	Threats        []types.Threat         `json:"threats"`
	Warnings       []types.Warning        `json:"warnings"`
	SimilarPackages []string              `json:"similar_packages,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
}

// CheckPackage performs threat analysis on a single package
func (e *Engine) CheckPackage(ctx context.Context, packageName, registry string) (*CheckPackageResult, error) {
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	
	logrus.Infof("Checking package %s from %s registry", packageName, registry)
	start := time.Now()

	// Create a dependency object for analysis
	dep := types.Dependency{
		Name:     packageName,
		Registry: registry,
		Direct:   true,
	}

	// Use default options for single package check
	options := &Options{
		DeepAnalysis:        true,
		SimilarityThreshold: 0.8,
	}

	// For single package analysis, we need to get popular packages for comparison
	popularPackages := e.getPopularPackagesForRegistry(registry)

	// Analyze the dependency
	threats, warnings := e.analyzeDependency(dep, popularPackages, options)

	// Determine overall threat level
	threatLevel := "none"
	maxConfidence := 0.0
	var similarPackages []string

	if len(threats) > 0 {
		// Sort threats by severity and confidence
		sort.Slice(threats, func(i, j int) bool {
			if threats[i].Severity != threats[j].Severity {
				return threats[i].Severity > threats[j].Severity
			}
			return threats[i].Confidence > threats[j].Confidence
		})

		// Use the highest severity threat to determine overall level
		highestThreat := threats[0]
		threatLevel = highestThreat.Severity.String()
		maxConfidence = highestThreat.Confidence

		// Collect similar packages from threats
		for _, threat := range threats {
			if threat.SimilarTo != "" {
				similarPackages = append(similarPackages, threat.SimilarTo)
			}
		}
	}

	// Create detailed analysis results
	details := map[string]interface{}{
		"analysis_duration": time.Since(start).String(),
		"checks_performed": []string{"lexical_similarity", "homoglyph_detection", "reputation_analysis"},
		"package_length":   len(packageName),
	}

	result := &CheckPackageResult{
		Package:         packageName,
		Registry:        registry,
		ThreatLevel:     threatLevel,
		Confidence:      maxConfidence,
		Threats:         threats,
		Warnings:        warnings,
		SimilarPackages: similarPackages,
		Details:         details,
	}

	logrus.Infof("Package check completed in %v. Threat level: %s, Confidence: %.2f", time.Since(start), threatLevel, maxConfidence)
	return result, nil
}

// getPopularPackagesForRegistry returns a list of popular packages for comparison
func (e *Engine) getPopularPackagesForRegistry(registry string) []string {
	// This is a simplified implementation. In a real system, this would
	// fetch from a database or cache of popular packages
	switch registry {
	case "npm":
		return []string{"react", "lodash", "express", "axios", "webpack", "babel", "eslint", "typescript", "jquery", "moment"}
	case "pypi":
		return []string{"numpy", "pandas", "requests", "flask", "django", "tensorflow", "pytorch", "scikit-learn", "matplotlib", "pillow"}
	default:
		return []string{}
	}
}

// Analyze performs threat analysis on the given dependencies
func (e *Engine) Analyze(ctx context.Context, deps []types.Dependency, options *Options) ([]types.Threat, []types.Warning, error) {
	logrus.Infof("Starting threat analysis for %d dependencies", len(deps))
	start := time.Now()

	var allThreats []types.Threat
	var allWarnings []types.Warning

	// Build package name index for similarity detection
	packageNames := make([]string, len(deps))
	for i, dep := range deps {
		packageNames[i] = dep.Name
	}

	// Analyze each dependency
	for _, dep := range deps {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		threats, warnings := e.analyzeDependency(dep, packageNames, options)
		allThreats = append(allThreats, threats...)
		allWarnings = append(allWarnings, warnings...)
	}

	// Sort threats by severity and confidence
	sort.Slice(allThreats, func(i, j int) bool {
		if allThreats[i].Severity != allThreats[j].Severity {
			return allThreats[i].Severity > allThreats[j].Severity
		}
		return allThreats[i].Confidence > allThreats[j].Confidence
	})

	duration := time.Since(start)
	logrus.Infof("Threat analysis completed in %v. Found %d threats, %d warnings", duration, len(allThreats), len(allWarnings))

	return allThreats, allWarnings, nil
}

// analyzeDependency analyzes a single dependency for threats
func (e *Engine) analyzeDependency(dep types.Dependency, allPackageNames []string, options *Options) ([]types.Threat, []types.Warning) {
	var threats []types.Threat
	var warnings []types.Warning

	// Skip analysis for very short package names (likely legitimate)
	if len(dep.Name) < e.config.Detection.MinPackageNameLength {
		return threats, warnings
	}

	// 1. Lexical similarity detection (typosquatting)
	if lexicalThreats := e.lexicalDetector.Detect(dep, allPackageNames, options.SimilarityThreshold); len(lexicalThreats) > 0 {
		threats = append(threats, lexicalThreats...)
	}

	// 1.5. Enhanced typosquatting detection with keyboard layout analysis
	if e.config.Detection.EnhancedTyposquatting {
		if enhancedThreats := e.enhancedTyposquattingDetector.DetectEnhanced(dep, allPackageNames, options.SimilarityThreshold); len(enhancedThreats) > 0 {
			threats = append(threats, enhancedThreats...)
		}
	}

	// 2. Homoglyph detection
	if e.config.Detection.HomoglyphDetection {
		if homoglyphThreats := e.homoglyphDetector.Detect(dep, allPackageNames); len(homoglyphThreats) > 0 {
			threats = append(threats, homoglyphThreats...)
		}
	}

	// 3. Dependency confusion detection
	if e.config.Detection.DependencyConfusion {
		if confusionThreats := e.detectDependencyConfusion(dep); len(confusionThreats) > 0 {
			threats = append(threats, confusionThreats...)
		}
	}

	// 4. Reputation-based analysis
	if e.config.Detection.ReputationScoring {
		if reputationThreats := e.reputationEngine.Analyze(dep); len(reputationThreats) > 0 {
			threats = append(threats, reputationThreats...)
		}
	}

	// 5. Package metadata analysis
	if metadataWarnings := e.analyzeMetadata(dep); len(metadataWarnings) > 0 {
		warnings = append(warnings, metadataWarnings...)
	}

	return threats, warnings
}

// detectDependencyConfusion detects potential dependency confusion attacks
func (e *Engine) detectDependencyConfusion(dep types.Dependency) []types.Threat {
	var threats []types.Threat

	// Check if package name matches private namespace patterns
	for _, regConfig := range e.config.Registries {
		for _, namespace := range regConfig.Private.Namespaces {
			if strings.HasPrefix(dep.Name, namespace) {
				// This looks like a private package but was found in public registry
				threat := types.Threat{
					ID:              generateThreatID(),
					Package:         dep.Name,
					Version:         dep.Version,
					Registry:        dep.Registry,
					Type:            types.ThreatTypeDependencyConfusion,
					Severity:        types.SeverityCritical,
					Confidence:      0.9,
					Description:     fmt.Sprintf("Package '%s' appears to be targeting private namespace '%s' but was found in public registry", dep.Name, namespace),
					Recommendation:  fmt.Sprintf("Verify that '%s' is the correct package and not a dependency confusion attack. Check your private registry configuration.", dep.Name),
					DetectedAt:      time.Now(),
					DetectionMethod: "dependency_confusion_namespace",
					Evidence: []types.Evidence{
						{
							Type:        "namespace_match",
							Description: "Package name matches private namespace pattern",
							Value:       namespace,
							Score:       0.9,
						},
						},
					}
					threats = append(threats, threat)
				}
			}
		}

	return threats
}

// analyzeMetadata analyzes package metadata for suspicious patterns
func (e *Engine) analyzeMetadata(dep types.Dependency) []types.Warning {
	var warnings []types.Warning

	// Check for missing or suspicious metadata
	if dep.Metadata.Description == "" {
		warnings = append(warnings, types.Warning{
			ID:         generateWarningID(),
			Package:    dep.Name,
			Version:    dep.Version,
			Registry:   dep.Registry,
			Type:       "missing_metadata",
			Message:    "Package has no description",
			Suggestion: "Verify package legitimacy - legitimate packages usually have descriptions",
			DetectedAt: time.Now(),
		})
	}

	// Check for suspicious install scripts
	if dep.Metadata.HasInstallScript {
		warnings = append(warnings, types.Warning{
			ID:         generateWarningID(),
			Package:    dep.Name,
			Version:    dep.Version,
			Registry:   dep.Registry,
			Type:       "install_script",
			Message:    "Package contains install/post-install scripts",
			Suggestion: "Review install scripts for malicious behavior before installation",
			DetectedAt: time.Now(),
		})
	}

	// Check for very new packages (potential supply chain risk)
	if dep.Metadata.PublishedAt != nil {
		age := time.Since(*dep.Metadata.PublishedAt)
		if age < 7*24*time.Hour { // Less than 7 days old
			warnings = append(warnings, types.Warning{
				ID:         generateWarningID(),
				Package:    dep.Name,
				Version:    dep.Version,
				Registry:   dep.Registry,
				Type:       "new_package",
				Message:    fmt.Sprintf("Package is very new (published %v ago)", age.Truncate(time.Hour)),
				Suggestion: "Exercise caution with very new packages - verify publisher reputation",
				DetectedAt: time.Now(),
			})
		}
	}

	// Check for packages with very few downloads (if available)
	if dep.Metadata.Downloads > 0 && dep.Metadata.Downloads < 100 {
		warnings = append(warnings, types.Warning{
			ID:         generateWarningID(),
			Package:    dep.Name,
			Version:    dep.Version,
			Registry:   dep.Registry,
			Type:       "low_downloads",
			Message:    fmt.Sprintf("Package has very few downloads (%d)", dep.Metadata.Downloads),
			Suggestion: "Verify package legitimacy - popular packages typically have more downloads",
			DetectedAt: time.Now(),
		})
	}

	return warnings
}

// LexicalDetector implements lexical similarity detection
type LexicalDetector struct {
	config *config.Config
}

// NewLexicalDetector creates a new lexical detector
func NewLexicalDetector(cfg *config.Config) *LexicalDetector {
	return &LexicalDetector{config: cfg}
}

// Detect performs lexical similarity detection
func (ld *LexicalDetector) Detect(target types.Dependency, allPackages []string, threshold float64) []types.Threat {
	var threats []types.Threat

	// Find similar package names
	for _, pkg := range allPackages {
		if pkg == target.Name {
			continue
		}

		// Calculate various similarity metrics
		levenshtein := ld.levenshteinSimilarity(target.Name, pkg)
		jaro := ld.jaroWinklerSimilarity(target.Name, pkg)
		transposition := ld.transpositionSimilarity(target.Name, pkg)

		// Use the highest similarity score
		maxSimilarity := math.Max(math.Max(levenshtein, jaro), transposition)

		if maxSimilarity >= threshold {
			severity := ld.calculateSeverity(maxSimilarity)
			
			threat := types.Threat{
				ID:              generateThreatID(),
				Package:         target.Name,
				Version:         target.Version,
				Registry:        target.Registry,
				Type:            types.ThreatTypeTyposquatting,
				Severity:        severity,
				Confidence:      maxSimilarity,
				Description:     fmt.Sprintf("Package name '%s' is very similar to '%s' (%.1f%% similarity)", target.Name, pkg, maxSimilarity*100),
				SimilarTo:       pkg,
				Recommendation:  fmt.Sprintf("Verify that '%s' is the intended package. Consider using '%s' instead if that was the intention.", target.Name, pkg),
				DetectedAt:      time.Now(),
				DetectionMethod: "lexical_similarity",
				Evidence: []types.Evidence{
					{
						Type:        "levenshtein_distance",
						Description: "Levenshtein similarity score",
						Value:       levenshtein,
						Score:       levenshtein,
					},
					{
						Type:        "jaro_winkler",
						Description: "Jaro-Winkler similarity score",
						Value:       jaro,
						Score:       jaro,
					},
				},
			}
			threats = append(threats, threat)
		}
	}

	return threats
}

// levenshteinSimilarity calculates Levenshtein similarity between two strings
func (ld *LexicalDetector) levenshteinSimilarity(s1, s2 string) float64 {
	distance := ld.levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func (ld *LexicalDetector) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = minInt(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// jaroWinklerSimilarity calculates Jaro-Winkler similarity
func (ld *LexicalDetector) jaroWinklerSimilarity(s1, s2 string) float64 {
	// Simplified Jaro-Winkler implementation
	if s1 == s2 {
		return 1.0
	}

	len1, len2 := len(s1), len(s2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	matchWindow := max(len1, len2)/2 - 1
	if matchWindow < 0 {
		matchWindow = 0
	}

	s1Matches := make([]bool, len1)
	s2Matches := make([]bool, len2)

	matches := 0
	transpositions := 0

	// Find matches
	for i := 0; i < len1; i++ {
		start := max(0, i-matchWindow)
		end := min(i+matchWindow+1, len2)

		for j := start; j < end; j++ {
			if s2Matches[j] || s1[i] != s2[j] {
				continue
			}
			s1Matches[i] = true
			s2Matches[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	// Count transpositions
	k := 0
	for i := 0; i < len1; i++ {
		if !s1Matches[i] {
			continue
		}
		for !s2Matches[k] {
			k++
		}
		if s1[i] != s2[k] {
			transpositions++
		}
		k++
	}

	jaro := (float64(matches)/float64(len1) + float64(matches)/float64(len2) + float64(matches-transpositions/2)/float64(matches)) / 3.0

	// Jaro-Winkler prefix bonus
	prefix := 0
	for i := 0; i < min(len1, len2) && i < 4; i++ {
		if s1[i] == s2[i] {
			prefix++
		} else {
			break
		}
	}

	return jaro + 0.1*float64(prefix)*(1.0-jaro)
}

// transpositionSimilarity detects character transpositions
func (ld *LexicalDetector) transpositionSimilarity(s1, s2 string) float64 {
	if len(s1) != len(s2) {
		return 0.0
	}

	differences := 0
	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			differences++
		}
	}

	// Check if it's a simple transposition (exactly 2 character swaps)
	if differences == 2 {
		// Find the differing positions
		var pos1, pos2 int = -1, -1
		for i := 0; i < len(s1); i++ {
			if s1[i] != s2[i] {
				if pos1 == -1 {
					pos1 = i
				} else {
					pos2 = i
					break
				}
			}
		}
		// Check if it's a transposition
		if pos1 != -1 && pos2 != -1 && s1[pos1] == s2[pos2] && s1[pos2] == s2[pos1] {
			return 0.95 // High similarity for transposition
		}
	}

	return 0.0
}

// calculateSeverity determines threat severity based on similarity score
func (ld *LexicalDetector) calculateSeverity(similarity float64) types.Severity {
	if similarity >= 0.95 {
		return types.SeverityCritical
	} else if similarity >= 0.9 {
		return types.SeverityHigh
	} else if similarity >= 0.8 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func generateThreatID() string {
	return fmt.Sprintf("threat_%d", time.Now().UnixNano())
}

func generateWarningID() string {
	return fmt.Sprintf("warning_%d", time.Now().UnixNano())
}

// minInt returns the minimum of multiple integers
func minInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	return min
}