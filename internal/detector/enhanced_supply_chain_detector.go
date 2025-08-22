package detector

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// EnhancedSupplyChainDetector provides comprehensive supply chain threat detection
type EnhancedSupplyChainDetector struct {
	metadataFilter    *ml.MetadataFilter
	typoDetector      *EnhancedTyposquattingDetector
	config            *SupplyChainConfig
	falsePositiveDB   *FalsePositiveDatabase
}

// SupplyChainConfig contains configuration for supply chain detection
type SupplyChainConfig struct {
	EnableMetadataFiltering   bool    `json:"enable_metadata_filtering"`
	EnableFalsePositiveFilter bool    `json:"enable_false_positive_filter"`
	MinConfidenceThreshold    float64 `json:"min_confidence_threshold"`
	MaxFalsePositiveRate      float64 `json:"max_false_positive_rate"`
	EnableAgeBasedFiltering   bool    `json:"enable_age_based_filtering"`
	EnableTechnologyFiltering bool    `json:"enable_technology_filtering"`
	EnablePopularityFiltering bool    `json:"enable_popularity_filtering"`
}

// FalsePositiveDatabase stores known false positive patterns
type FalsePositiveDatabase struct {
	KnownFalsePositives map[string]FalsePositiveEntry `json:"known_false_positives"`
	PatternFilters      []PatternFilter               `json:"pattern_filters"`
	TechnologyMismatches []TechnologyMismatch         `json:"technology_mismatches"`
}

// FalsePositiveEntry represents a known false positive
type FalsePositiveEntry struct {
	PackageName     string    `json:"package_name"`
	Registry        string    `json:"registry"`
	Reason          string    `json:"reason"`
	ConfirmedAt     time.Time `json:"confirmed_at"`
	ConfidenceScore float64   `json:"confidence_score"`
}

// PatternFilter represents a pattern-based filter
type PatternFilter struct {
	Pattern     string  `json:"pattern"`
	FilterType  string  `json:"filter_type"` // "exclude", "reduce_confidence"
	Reason      string  `json:"reason"`
	Confidence  float64 `json:"confidence"`
}

// TechnologyMismatch represents technology-specific filtering
type TechnologyMismatch struct {
	CVEPattern      string   `json:"cve_pattern"`
	Technologies    []string `json:"technologies"`
	ExcludedTechs   []string `json:"excluded_techs"`
	Reason          string   `json:"reason"`
}

// EnhancedThreatResult contains comprehensive threat analysis results
type EnhancedThreatResult struct {
	Package              string                    `json:"package"`
	Registry             string                    `json:"registry"`
	ThreatType           string                    `json:"threat_type"`
	Severity             string                    `json:"severity"`
	ConfidenceScore      float64                   `json:"confidence_score"`
	IsFiltered           bool                      `json:"is_filtered"`
	FilterReasons        []string                  `json:"filter_reasons"`
	MetadataAnalysis     *ml.MetadataAnalysis      `json:"metadata_analysis"`
	TyposquattingAnalysis *TyposquattingAnalysis   `json:"typosquatting_analysis"`
	SupplyChainRisk      float64                   `json:"supply_chain_risk"`
	Recommendations      []string                  `json:"recommendations"`
	Evidence             []Evidence                `json:"evidence"`
	FalsePositiveRisk    float64                   `json:"false_positive_risk"`
}

// Evidence represents evidence for a threat
type Evidence struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"`
	Data        interface{} `json:"data"`
}

// NewEnhancedSupplyChainDetector creates a new enhanced supply chain detector
func NewEnhancedSupplyChainDetector() *EnhancedSupplyChainDetector {
	return &EnhancedSupplyChainDetector{
		metadataFilter: ml.NewMetadataFilter(),
		typoDetector:   NewEnhancedTyposquattingDetector(),
		config: &SupplyChainConfig{
			EnableMetadataFiltering:   true,
			EnableFalsePositiveFilter: true,
			MinConfidenceThreshold:    0.7,
			MaxFalsePositiveRate:      0.1,
			EnableAgeBasedFiltering:   true,
			EnableTechnologyFiltering: true,
			EnablePopularityFiltering: true,
		},
		falsePositiveDB: NewFalsePositiveDatabase(),
	}
}

// DetectThreats performs comprehensive threat detection with enhanced filtering
func (escd *EnhancedSupplyChainDetector) DetectThreats(ctx context.Context, packages []types.Package) ([]*EnhancedThreatResult, error) {
	var results []*EnhancedThreatResult

	for _, pkg := range packages {
		result, err := escd.analyzePackage(ctx, &pkg)
		if err != nil {
			continue // Log error but continue processing
		}

		// Apply filtering
		if escd.config.EnableFalsePositiveFilter {
			escd.applyFalsePositiveFiltering(result)
		}

		// Only include results that pass confidence threshold
		if !result.IsFiltered && result.ConfidenceScore >= escd.config.MinConfidenceThreshold {
			results = append(results, result)
		}
	}

	return results, nil
}

// analyzePackage performs comprehensive analysis of a single package
func (escd *EnhancedSupplyChainDetector) analyzePackage(ctx context.Context, pkg *types.Package) (*EnhancedThreatResult, error) {
	result := &EnhancedThreatResult{
		Package:         pkg.Name,
		Registry:        pkg.Registry,
		FilterReasons:   []string{},
		Recommendations: []string{},
		Evidence:        []Evidence{},
	}

	// Convert package to metadata format
	metadata := escd.convertToMetadata(pkg)

	// Perform metadata analysis
	if escd.config.EnableMetadataFiltering {
		metadataAnalysis, err := escd.metadataFilter.AnalyzeMetadata(ctx, metadata)
		if err == nil {
			result.MetadataAnalysis = metadataAnalysis
			
			// Check if package should be filtered based on metadata
			if !metadataAnalysis.IsLegitimate {
				result.IsFiltered = true
				result.FilterReasons = append(result.FilterReasons, metadataAnalysis.FilterReasons...)
			}
		}
	}

	// Perform typosquatting analysis
	typoAnalysis := escd.analyzeTyposquatting(pkg)
	result.TyposquattingAnalysis = &typoAnalysis

	// Calculate overall threat scores
	escd.calculateThreatScores(result)

	// Generate recommendations
	escd.generateRecommendations(result)

	return result, nil
}

// analyzeTyposquatting performs enhanced typosquatting analysis
func (escd *EnhancedSupplyChainDetector) analyzeTyposquatting(pkg *types.Package) TyposquattingAnalysis {
	analysis := TyposquattingAnalysis{}

	// Get popular packages for comparison
	popularPackages := escd.getPopularPackages(pkg.Registry)

	var bestMatch string
	var highestSimilarity float64

	for _, popular := range popularPackages {
		if pkg.Name == popular {
			continue
		}

		similarity := escd.calculateSimilarity(pkg.Name, popular)
		if similarity > highestSimilarity {
			highestSimilarity = similarity
			bestMatch = popular
		}
	}

	// Use existing TyposquattingAnalysis structure
	analysis.EditDistance = escd.calculateEditDistance(pkg.Name, bestMatch)
	analysis.VisualSimilarity = highestSimilarity
	analysis.PhoneticSimilarity = 0.5 // Default value for now

	// Store additional info in PrimaryType field
	analysis.PrimaryType = bestMatch

	return analysis
}

// calculateThreatScores calculates overall threat scores
func (escd *EnhancedSupplyChainDetector) calculateThreatScores(result *EnhancedThreatResult) {
	var confidenceScore float64
	var supplyChainRisk float64

	// Factor in metadata analysis
	if result.MetadataAnalysis != nil {
		confidenceScore += result.MetadataAnalysis.ConfidenceScore * 0.4
		supplyChainRisk += result.MetadataAnalysis.SupplyChainRisk * 0.3
		
		// High typosquatting risk significantly impacts confidence
		if result.MetadataAnalysis.TyposquattingRisk > 0.7 {
			confidenceScore += 0.3
			supplyChainRisk += 0.4
		}
	}

	// Factor in typosquatting analysis
	if result.TyposquattingAnalysis != nil {
		// Use visual similarity as confidence proxy
		confidenceScore += result.TyposquattingAnalysis.VisualSimilarity * 0.3
		
		// High edit distance indicates potential typosquatting
		if result.TyposquattingAnalysis.EditDistance <= 2 && result.TyposquattingAnalysis.VisualSimilarity > 0.7 {
			supplyChainRisk += 0.2
		}
	}

	// Calculate false positive risk
	result.FalsePositiveRisk = escd.calculateFalsePositiveRisk(result)

	// Adjust confidence based on false positive risk
	confidenceScore = confidenceScore * (1.0 - result.FalsePositiveRisk)

	result.ConfidenceScore = math.Min(1.0, confidenceScore)
	result.SupplyChainRisk = math.Min(1.0, supplyChainRisk)

	// Determine threat type and severity
	escd.classifyThreat(result)
}

// calculateFalsePositiveRisk calculates the risk of false positive
func (escd *EnhancedSupplyChainDetector) calculateFalsePositiveRisk(result *EnhancedThreatResult) float64 {
	risk := 0.0

	// Check against known false positive patterns
	for _, filter := range escd.falsePositiveDB.PatternFilters {
		if escd.matchesPattern(result.Package, filter.Pattern) {
			if filter.FilterType == "exclude" {
				return 1.0 // Definitely a false positive
			} else if filter.FilterType == "reduce_confidence" {
				risk += 0.3
			}
		}
	}

	// Enhanced context-aware filtering
	if result.MetadataAnalysis != nil {
		// Technology mismatch increases false positive risk
		if result.MetadataAnalysis.TechnologyAlignment < 0.3 {
			risk += 0.4
		}

		// Very low popularity might indicate false positive
		if result.MetadataAnalysis.PopularityScore < 0.1 {
			risk += 0.2
		}

		// High quality metadata reduces false positive risk
		if result.MetadataAnalysis.MetadataQuality > 0.8 {
			risk -= 0.2
		}

		// Well-maintained packages are less likely to be false positives
		if result.MetadataAnalysis.MaintainerTrustScore > 0.7 {
			risk -= 0.15
		}

		// Established packages with good reputation
		if result.MetadataAnalysis.PopularityScore > 0.5 && result.MetadataAnalysis.MetadataQuality > 0.6 {
			risk -= 0.25
		}
	}

	// Typosquatting analysis context
	if result.TyposquattingAnalysis != nil {
		// Very high similarity might be legitimate (e.g., official variants)
		if result.TyposquattingAnalysis.VisualSimilarity > 0.95 {
			risk += 0.3
		}

		// Check for legitimate package variations - these should have LOWER false positive risk
		if escd.isLegitimateVariation(result.Package, result.TyposquattingAnalysis.PrimaryType) {
			risk -= 0.6 // Significantly reduce false positive risk for legitimate variations
		}
	}

	// Registry-specific filtering
	risk += escd.calculateRegistrySpecificRisk(result)

	return math.Max(0.0, math.Min(1.0, risk))
}

// applyFalsePositiveFiltering applies false positive filtering
func (escd *EnhancedSupplyChainDetector) applyFalsePositiveFiltering(result *EnhancedThreatResult) {
	// Check against known false positives
	key := fmt.Sprintf("%s:%s", result.Registry, result.Package)
	if entry, exists := escd.falsePositiveDB.KnownFalsePositives[key]; exists {
		result.IsFiltered = true
		result.FilterReasons = append(result.FilterReasons, fmt.Sprintf("known_false_positive: %s", entry.Reason))
		return
	}

	// Apply pattern-based filtering
	for _, filter := range escd.falsePositiveDB.PatternFilters {
		if escd.matchesPattern(result.Package, filter.Pattern) && filter.FilterType == "exclude" {
			result.IsFiltered = true
			result.FilterReasons = append(result.FilterReasons, fmt.Sprintf("pattern_filter: %s", filter.Reason))
			return
		}
	}

	// Enhanced intelligent filtering
	if escd.shouldFilterByContext(result) {
		result.IsFiltered = true
		return
	}

	// High false positive risk
	if result.FalsePositiveRisk > 0.8 {
		result.IsFiltered = true
		result.FilterReasons = append(result.FilterReasons, "high_false_positive_risk")
	}

	// Apply confidence-based filtering with context
	if escd.shouldReduceConfidence(result) {
		originalConfidence := result.ConfidenceScore
		result.ConfidenceScore *= 0.7 // Reduce confidence by 30%
		result.FilterReasons = append(result.FilterReasons, 
			fmt.Sprintf("confidence_reduced: %.2f -> %.2f", originalConfidence, result.ConfidenceScore))
	}
}

// generateRecommendations generates actionable recommendations
func (escd *EnhancedSupplyChainDetector) generateRecommendations(result *EnhancedThreatResult) {
	if result.IsFiltered {
		result.Recommendations = append(result.Recommendations, "Package filtered as likely false positive")
		return
	}

	if result.SupplyChainRisk > 0.7 {
		result.Recommendations = append(result.Recommendations, "High supply chain risk - avoid this package")
		result.Recommendations = append(result.Recommendations, "Use official package alternatives")
	}

	if result.TyposquattingAnalysis != nil && result.TyposquattingAnalysis.VisualSimilarity > 0.8 {
		result.Recommendations = append(result.Recommendations, 
			fmt.Sprintf("Potential typosquatting of '%s' - verify package name", result.TyposquattingAnalysis.PrimaryType))
	}

	if result.MetadataAnalysis != nil {
		if result.MetadataAnalysis.PopularityScore < 0.2 {
			result.Recommendations = append(result.Recommendations, "Low usage package - verify legitimacy")
		}
		
		if len(result.MetadataAnalysis.RiskFactors) > 3 {
			result.Recommendations = append(result.Recommendations, "Multiple risk factors detected - thorough review recommended")
		}
	}
}

// classifyThreat classifies the threat type and severity
func (escd *EnhancedSupplyChainDetector) classifyThreat(result *EnhancedThreatResult) {
	if result.SupplyChainRisk > 0.8 {
		result.Severity = "CRITICAL"
	} else if result.SupplyChainRisk > 0.6 {
		result.Severity = "HIGH"
	} else if result.SupplyChainRisk > 0.4 {
		result.Severity = "MEDIUM"
	} else {
		result.Severity = "LOW"
	}

	// Determine threat type
	if result.TyposquattingAnalysis != nil && result.TyposquattingAnalysis.VisualSimilarity > 0.7 {
		result.ThreatType = "TYPOSQUATTING"
	} else if result.MetadataAnalysis != nil && len(result.MetadataAnalysis.RiskFactors) > 2 {
		result.ThreatType = "SUSPICIOUS_PACKAGE"
	} else {
		result.ThreatType = "POTENTIAL_RISK"
	}
}

// Helper methods

func (escd *EnhancedSupplyChainDetector) convertToMetadata(pkg *types.Package) *ml.PackageMetadata {
	metadata := &ml.PackageMetadata{
		Name:     pkg.Name,
		Version:  pkg.Version,
		Registry: pkg.Registry,
	}
	
	// Populate from package metadata if available
	if pkg.Metadata != nil {
		metadata.Description = pkg.Metadata.Description
		metadata.CreatedAt = pkg.Metadata.CreatedAt
		metadata.UpdatedAt = pkg.Metadata.UpdatedAt
		metadata.Maintainers = pkg.Metadata.Maintainers
		metadata.Repository = pkg.Metadata.Repository
		metadata.License = pkg.Metadata.License
		metadata.Keywords = pkg.Metadata.Keywords
		metadata.Homepage = pkg.Metadata.Homepage
	}
	
	return metadata
}

func (escd *EnhancedSupplyChainDetector) getPopularPackages(registry string) []string {
	popularPackages := map[string][]string{
		"npm": {"react", "lodash", "express", "axios", "webpack", "babel", "eslint", "typescript", "vue", "angular"},
		"pypi": {"requests", "numpy", "pandas", "flask", "django", "tensorflow"},
		"rubygems": {"rails", "bundler", "rake", "rspec", "puma", "nokogiri"},
	}
	
	if packages, exists := popularPackages[registry]; exists {
		return packages
	}
	return []string{}
}

func (escd *EnhancedSupplyChainDetector) calculateSimilarity(s1, s2 string) float64 {
	if s2 == "" {
		return 0.0
	}
	distance := escd.calculateEditDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

func (escd *EnhancedSupplyChainDetector) calculateEditDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				min(matrix[i-1][j]+1, matrix[i][j-1]+1),
				matrix[i-1][j-1]+cost,
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

func (escd *EnhancedSupplyChainDetector) calculateTypoConfidence(pkg *types.Package, analysis TyposquattingAnalysis) float64 {
	confidence := analysis.VisualSimilarity

	// Adjust based on edit distance
	if analysis.EditDistance <= 1 {
		confidence += 0.2
	} else if analysis.EditDistance <= 2 {
		confidence += 0.1
	}

	// Adjust based on phonetic similarity
	confidence += analysis.PhoneticSimilarity * 0.1

	return math.Min(1.0, confidence)
}

func (escd *EnhancedSupplyChainDetector) hasCharacterSubstitution(candidate, target string) bool {
	if len(candidate) != len(target) {
		return false
	}

	substitutions := map[rune][]rune{
		'0': {'o', 'O'},
		'1': {'l', 'I', 'i'},
		'5': {'s', 'S'},
		'8': {'b', 'B'},
	}

	diffCount := 0
	for i, r1 := range candidate {
		r2 := rune(target[i])
		if r1 != r2 {
			diffCount++
			if diffCount > 2 {
				return false
			}
			
			// Check if it's a known substitution
			if subs, exists := substitutions[r1]; exists {
				found := false
				for _, sub := range subs {
					if sub == r2 {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}

	return diffCount > 0 && diffCount <= 2
}

func (escd *EnhancedSupplyChainDetector) hasHomographs(candidate, target string) bool {
	// Simplified homograph detection
	homographs := map[string]string{
		"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
	}

	normalizedCandidate := candidate
	for cyrillic, latin := range homographs {
		normalizedCandidate = strings.ReplaceAll(normalizedCandidate, cyrillic, latin)
	}

	return normalizedCandidate == target && normalizedCandidate != candidate
}

func (escd *EnhancedSupplyChainDetector) hasKeyboardErrors(candidate, target string) bool {
	// Simplified keyboard proximity check
	proximityMap := map[rune][]rune{
		'q': {'w', 'a'}, 'w': {'q', 'e', 's'}, 'e': {'w', 'r', 'd'},
		'a': {'q', 's', 'z'}, 's': {'a', 'd', 'w', 'x'}, 'd': {'s', 'f', 'e', 'c'},
	}

	if len(candidate) != len(target) {
		return false
	}

	errorCount := 0
	for i, r1 := range candidate {
		r2 := rune(target[i])
		if r1 != r2 {
			errorCount++
			if errorCount > 1 {
				return false
			}
			
			if adjacent, exists := proximityMap[r1]; exists {
				found := false
				for _, adj := range adjacent {
					if adj == r2 {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}

	return errorCount == 1
}

func (escd *EnhancedSupplyChainDetector) hasVersionConfusion(candidate, target string) bool {
	// Check for version/suffix additions
	suffixes := []string{"2", "js", "node", "v2", "next", "new"}
	
	for _, suffix := range suffixes {
		if candidate == target+suffix {
			return true
		}
	}
	
	return false
}

func (escd *EnhancedSupplyChainDetector) hasNamespaceConfusion(candidate, target string) bool {
	// Check for namespace-like patterns
	if strings.Contains(candidate, "-") && strings.Contains(target, "-") {
		candidateParts := strings.Split(candidate, "-")
		targetParts := strings.Split(target, "-")
		
		if len(candidateParts) == len(targetParts) {
			diffCount := 0
			for i, part1 := range candidateParts {
				if part1 != targetParts[i] {
					diffCount++
				}
			}
			return diffCount == 1
		}
	}
	
	return false
}

func (escd *EnhancedSupplyChainDetector) matchesPattern(text, pattern string) bool {
	// Simple pattern matching - would be enhanced with regex
	return strings.Contains(strings.ToLower(text), strings.ToLower(pattern))
}

// NewFalsePositiveDatabase creates a new false positive database with default entries
func NewFalsePositiveDatabase() *FalsePositiveDatabase {
	knownFalsePositives := make(map[string]FalsePositiveEntry)
	
	// Add common legitimate package variations
	legitimatePackages := map[string]string{
		"npm:react-dom":        "Official React DOM package",
		"npm:react-router":     "Official React Router package",
		"npm:react-native":     "Official React Native package",
		"npm:react-scripts":    "Official Create React App scripts",
		"npm:lodash-es":        "Official Lodash ES modules package",
		"npm:lodash.debounce":  "Official Lodash debounce utility",
		"npm:lodash.merge":     "Official Lodash merge utility",
		"npm:express-session": "Official Express session middleware",
		"npm:express-validator": "Official Express validator middleware",
		"npm:angular-cli":      "Official Angular CLI package",
		"npm:angular-core":     "Official Angular core package",
		"npm:angular-common":   "Official Angular common package",
		"npm:vue-router":       "Official Vue Router package",
		"npm:vue-cli":          "Official Vue CLI package",
		"npm:vuex":             "Official Vue state management",
	}
	
	for key, reason := range legitimatePackages {
		knownFalsePositives[key] = FalsePositiveEntry{
			PackageName:     strings.Split(key, ":")[1],
			Registry:        strings.Split(key, ":")[0],
			Reason:          reason,
			ConfirmedAt:     time.Now(),
			ConfidenceScore: 0.95,
		}
	}
	
	return &FalsePositiveDatabase{
		KnownFalsePositives: knownFalsePositives,
		PatternFilters: []PatternFilter{
			{
				Pattern:    "content-type",
				FilterType: "reduce_confidence",
				Reason:     "legitimate_npm_package",
				Confidence: 0.9,
			},
			{
				Pattern:    "content-disposition", 
				FilterType: "reduce_confidence",
				Reason:     "legitimate_npm_package",
				Confidence: 0.9,
			},
			{
				Pattern:    "accepts",
				FilterType: "reduce_confidence", 
				Reason:     "legitimate_npm_package",
				Confidence: 0.9,
			},
			// Pattern filters for legitimate package variations
			{
				Pattern:    ".*-dom$",
				FilterType: "reduce_confidence",
				Reason:     "legitimate_dom_package_variation",
				Confidence: 0.8,
			},
			{
				Pattern:    ".*-es$",
				FilterType: "reduce_confidence",
				Reason:     "legitimate_es_module_variation",
				Confidence: 0.8,
			},
			{
				Pattern:    ".*-session$",
				FilterType: "reduce_confidence",
				Reason:     "legitimate_session_middleware",
				Confidence: 0.8,
			},
		},
		TechnologyMismatches: []TechnologyMismatch{
			{
				CVEPattern:    "CVE-.*-.*",
				Technologies:  []string{"npm", "javascript", "node"},
				ExcludedTechs: []string{"java", "python", "ruby", "php"},
				Reason:        "technology_mismatch",
			},
		},
	}
}

// isLegitimateVariation checks if a package is a legitimate variation of another
func (escd *EnhancedSupplyChainDetector) isLegitimateVariation(candidate, target string) bool {
	// Common legitimate variations
	legitimatePatterns := map[string][]string{
		"react": {"react-dom", "react-router", "react-native", "react-scripts"},
		"angular": {"angular-cli", "angular-core", "angular-common"},
		"vue": {"vue-router", "vue-cli", "vuex"},
		"express": {"express-session", "express-validator"},
		"lodash": {"lodash-es", "lodash.debounce", "lodash.merge"},
	}

	if variations, exists := legitimatePatterns[target]; exists {
		for _, variation := range variations {
			if candidate == variation {
				return true
			}
		}
	}

	// Check for official scoped packages
	if strings.HasPrefix(candidate, "@") && strings.Contains(candidate, "/"+target) {
		return true
	}

	return false
}

// calculateRegistrySpecificRisk calculates registry-specific false positive risk
func (escd *EnhancedSupplyChainDetector) calculateRegistrySpecificRisk(result *EnhancedThreatResult) float64 {
	risk := 0.0

	switch result.Registry {
	case "npm":
		// NPM has many legitimate scoped packages
		if strings.HasPrefix(result.Package, "@") {
			risk -= 0.1
		}
		// Common NPM patterns that are usually legitimate
		if strings.Contains(result.Package, "-types") || strings.Contains(result.Package, "-cli") {
			risk -= 0.15
		}
	case "pypi":
		// Python packages with underscores are common
		if strings.Contains(result.Package, "_") {
			risk -= 0.05
		}
	case "rubygems":
		// Ruby gems with dashes are common
		if strings.Contains(result.Package, "-") {
			risk -= 0.05
		}
	}

	return risk
}

// shouldFilterByContext determines if a threat should be filtered based on context
func (escd *EnhancedSupplyChainDetector) shouldFilterByContext(result *EnhancedThreatResult) bool {
	// Filter if confidence is very low and metadata quality is high
	if result.ConfidenceScore < 0.3 && result.MetadataAnalysis != nil {
		if result.MetadataAnalysis.MetadataQuality > 0.7 {
			result.FilterReasons = append(result.FilterReasons, "low_confidence_high_quality")
			return true
		}
	}

	// Filter if package has high trust scores but low threat confidence
	if result.MetadataAnalysis != nil {
		if result.MetadataAnalysis.MaintainerTrustScore > 0.8 && 
		   result.MetadataAnalysis.RepositoryTrustScore > 0.8 && 
		   result.ConfidenceScore < 0.5 {
			result.FilterReasons = append(result.FilterReasons, "high_trust_low_threat")
			return true
		}
	}

	// Filter if package is very popular but threat confidence is moderate
	if result.MetadataAnalysis != nil {
		if result.MetadataAnalysis.PopularityScore > 0.8 && result.ConfidenceScore < 0.6 {
			result.FilterReasons = append(result.FilterReasons, "popular_package_moderate_threat")
			return true
		}
	}

	return false
}

// shouldReduceConfidence determines if confidence should be reduced based on context
func (escd *EnhancedSupplyChainDetector) shouldReduceConfidence(result *EnhancedThreatResult) bool {
	// Reduce confidence for packages with mixed signals
	if result.MetadataAnalysis != nil {
		// Good metadata but moderate threat
		if result.MetadataAnalysis.MetadataQuality > 0.6 && 
		   result.ConfidenceScore > 0.5 && result.ConfidenceScore < 0.8 {
			return true
		}

		// Decent popularity but suspicious patterns
		if result.MetadataAnalysis.PopularityScore > 0.3 && 
		   result.ConfidenceScore > 0.6 && result.ConfidenceScore < 0.9 {
			return true
		}
	}

	// Reduce confidence for typosquatting with very high similarity (might be legitimate)
	if result.TyposquattingAnalysis != nil {
		if result.TyposquattingAnalysis.VisualSimilarity > 0.9 && result.ConfidenceScore > 0.7 {
			return true
		}
	}

	return false
}