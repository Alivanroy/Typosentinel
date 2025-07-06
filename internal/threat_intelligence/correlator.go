package threat_intelligence

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ThreatCorrelator correlates packages with threat intelligence data
type ThreatCorrelator struct {
	db               *ThreatDatabase
	logger           *logger.Logger
	mu               sync.RWMutex
	cache            map[string]*CachedCorrelation
	cacheExpiry      time.Duration
	matchingRules    []MatchingRule
	severityWeights  map[string]float64
	confidenceThreshold float64
}

// CachedCorrelation represents a cached correlation result
type CachedCorrelation struct {
	Result    *ThreatCorrelationResult
	Timestamp time.Time
}

// MatchingRule represents a rule for matching packages to threats
type MatchingRule struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // "exact", "pattern", "similarity", "custom"
	Pattern     string                 `json:"pattern,omitempty"`
	Weight      float64                `json:"weight"`
	Enabled     bool                   `json:"enabled"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Matcher     MatcherFunc            `json:"-"`
}

// MatcherFunc is a function that matches a package against a threat
type MatcherFunc func(pkg *types.Package, threat *ThreatIntelligence, config map[string]interface{}) (*ThreatMatch, error)

// CorrelationConfig represents correlation configuration
type CorrelationConfig struct {
	CacheExpiry         time.Duration          `json:"cache_expiry"`
	ConfidenceThreshold float64                `json:"confidence_threshold"`
	SeverityWeights     map[string]float64     `json:"severity_weights"`
	MatchingRules       []MatchingRule         `json:"matching_rules"`
	MaxMatches          int                    `json:"max_matches"`
	ParallelProcessing  bool                   `json:"parallel_processing"`
}

// NewThreatCorrelator creates a new threat correlator
func NewThreatCorrelator(logger *logger.Logger) *ThreatCorrelator {
	return &ThreatCorrelator{
		logger:              logger,
		cache:               make(map[string]*CachedCorrelation),
		cacheExpiry:         15 * time.Minute,
		confidenceThreshold: 0.5,
		severityWeights: map[string]float64{
			"critical": 1.0,
			"high":     0.8,
			"medium":   0.6,
			"low":      0.4,
			"info":     0.2,
		},
	}
}

// Initialize sets up the threat correlator
func (tc *ThreatCorrelator) Initialize(ctx context.Context, db *ThreatDatabase) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.db = db

	// Initialize default matching rules
	tc.initializeMatchingRules()

	// Start cache cleanup routine
	go tc.startCacheCleanup(ctx)

	tc.logger.Info("Threat correlator initialized", map[string]interface{}{
		"cache_expiry":         tc.cacheExpiry,
		"confidence_threshold": tc.confidenceThreshold,
		"matching_rules":       len(tc.matchingRules),
	})

	return nil
}

// CorrelatePackage correlates a package with threat intelligence
func (tc *ThreatCorrelator) CorrelatePackage(ctx context.Context, pkg *types.Package) (*ThreatCorrelationResult, error) {
	cacheKey := tc.generateCacheKey(pkg)

	// Check cache first
	if cached := tc.getCachedResult(cacheKey); cached != nil {
		tc.logger.Debug("Using cached correlation result", map[string]interface{}{
			"package":   pkg.Name,
			"ecosystem": pkg.Type,
		})
		return cached, nil
	}

	start := time.Now()
	tc.logger.Debug("Starting threat correlation", map[string]interface{}{
		"package":   pkg.Name,
		"ecosystem": pkg.Type,
	})

	// Search for relevant threats
	threats, err := tc.findRelevantThreats(ctx, pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to find relevant threats: %w", err)
	}

	// Correlate package with threats
	matches, err := tc.correlateWithThreats(ctx, pkg, threats)
	if err != nil {
		return nil, fmt.Errorf("failed to correlate with threats: %w", err)
	}

	// Calculate overall severity and confidence
	overallSeverity, confidenceScore := tc.calculateOverallRisk(matches)

	// Generate recommendations
	recommendations := tc.generateRecommendations(pkg, matches, overallSeverity)

	result := &ThreatCorrelationResult{
		PackageName:     pkg.Name,
		Matches:         matches,
		OverallSeverity: overallSeverity,
		ConfidenceScore: confidenceScore,
		Recommendations: recommendations,
		LastUpdated:     time.Now(),
	}

	// Cache the result
	tc.cacheResult(cacheKey, result)

	tc.logger.Info("Threat correlation completed", map[string]interface{}{
		"package":          pkg.Name,
		"ecosystem":        pkg.Type,
		"matches":          len(matches),
		"overall_severity": overallSeverity,
		"confidence_score": confidenceScore,
		"duration":         time.Since(start),
	})

	return result, nil
}

// UpdateConfiguration updates the correlator configuration
func (tc *ThreatCorrelator) UpdateConfiguration(config *CorrelationConfig) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if config.CacheExpiry > 0 {
		tc.cacheExpiry = config.CacheExpiry
	}

	if config.ConfidenceThreshold > 0 {
		tc.confidenceThreshold = config.ConfidenceThreshold
	}

	if config.SeverityWeights != nil {
		tc.severityWeights = config.SeverityWeights
	}

	if config.MatchingRules != nil {
		tc.matchingRules = config.MatchingRules
		// Initialize matcher functions for rules
		for i := range tc.matchingRules {
			tc.initializeMatcherFunc(&tc.matchingRules[i])
		}
	}

	// Clear cache to force re-evaluation with new config
	tc.cache = make(map[string]*CachedCorrelation)

	tc.logger.Info("Threat correlator configuration updated")
	return nil
}

// GetStatistics returns correlation statistics
func (tc *ThreatCorrelator) GetStatistics() map[string]interface{} {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["cache_size"] = len(tc.cache)
	stats["cache_expiry"] = tc.cacheExpiry
	stats["confidence_threshold"] = tc.confidenceThreshold
	stats["matching_rules"] = len(tc.matchingRules)
	stats["severity_weights"] = tc.severityWeights

	return stats
}

// ClearCache clears the correlation cache
func (tc *ThreatCorrelator) ClearCache() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache = make(map[string]*CachedCorrelation)
	tc.logger.Info("Threat correlation cache cleared")
}

// Helper methods

func (tc *ThreatCorrelator) findRelevantThreats(ctx context.Context, pkg *types.Package) ([]ThreatIntelligence, error) {
	// Search for exact package name matches
	exactQuery := &ThreatQuery{
		PackageName: pkg.Name,
		Ecosystem:   pkg.Type,
		Limit:       1000,
	}

	exactResult, err := tc.db.SearchThreats(ctx, exactQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to search exact threats: %w", err)
	}

	threats := exactResult.Threats

	// Search for pattern-based matches
	patternThreats, err := tc.findPatternThreats(ctx, pkg)
	if err != nil {
		tc.logger.Warn("Failed to find pattern threats", map[string]interface{}{
			"error": err,
		})
	} else {
		threats = append(threats, patternThreats...)
	}

	// Search for similarity-based matches
	similarityThreats, err := tc.findSimilarityThreats(ctx, pkg)
	if err != nil {
		tc.logger.Warn("Failed to find similarity threats", map[string]interface{}{
			"error": err,
		})
	} else {
		threats = append(threats, similarityThreats...)
	}

	// Remove duplicates
	threats = tc.removeDuplicateThreats(threats)

	return threats, nil
}

func (tc *ThreatCorrelator) findPatternThreats(ctx context.Context, pkg *types.Package) ([]ThreatIntelligence, error) {
	// Search for threats with patterns that might match the package
	query := &ThreatQuery{
		Ecosystem: pkg.Type,
		Limit:     1000,
	}

	result, err := tc.db.SearchThreats(ctx, query)
	if err != nil {
		return nil, err
	}

	var matchingThreats []ThreatIntelligence
	for _, threat := range result.Threats {
		// Check if any indicators match the package
		for _, indicator := range threat.Indicators {
			if indicator.Type == "pattern" {
				matched, err := regexp.MatchString(indicator.Value, pkg.Name)
				if err != nil {
					continue
				}
				if matched {
					matchingThreats = append(matchingThreats, threat)
					break
				}
			}
		}
	}

	return matchingThreats, nil
}

func (tc *ThreatCorrelator) findSimilarityThreats(ctx context.Context, pkg *types.Package) ([]ThreatIntelligence, error) {
	// This is a simplified similarity search
	// In a real implementation, you might use more sophisticated algorithms
	query := &ThreatQuery{
		Ecosystem: pkg.Type,
		Limit:     1000,
	}

	result, err := tc.db.SearchThreats(ctx, query)
	if err != nil {
		return nil, err
	}

	var similarThreats []ThreatIntelligence
	for _, threat := range result.Threats {
		// Calculate similarity between package name and threat package name
		similarity := tc.calculateStringSimilarity(pkg.Name, threat.PackageName)
		if similarity > 0.8 { // 80% similarity threshold
			similarThreats = append(similarThreats, threat)
		}
	}

	return similarThreats, nil
}

func (tc *ThreatCorrelator) correlateWithThreats(ctx context.Context, pkg *types.Package, threats []ThreatIntelligence) ([]ThreatMatch, error) {
	var matches []ThreatMatch

	for _, threat := range threats {
		for _, rule := range tc.matchingRules {
			if !rule.Enabled {
				continue
			}

			match, err := tc.applyMatchingRule(pkg, &threat, &rule)
			if err != nil {
				tc.logger.Warn("Failed to apply matching rule", map[string]interface{}{
				"rule":  rule.Name,
				"error": err,
			})
				continue
			}

			if match != nil {
				matches = append(matches, *match)
			}
		}
	}

	// Sort matches by confidence (highest first)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].MatchConfidence > matches[j].MatchConfidence
	})

	// Limit number of matches
	maxMatches := 50
	if len(matches) > maxMatches {
		matches = matches[:maxMatches]
	}

	return matches, nil
}

func (tc *ThreatCorrelator) applyMatchingRule(pkg *types.Package, threat *ThreatIntelligence, rule *MatchingRule) (*ThreatMatch, error) {
	if rule.Matcher != nil {
		return rule.Matcher(pkg, threat, rule.Config)
	}

	// Default matching logic based on rule type
	switch rule.Type {
	case "exact":
		return tc.exactMatch(pkg, threat, rule)
	case "pattern":
		return tc.patternMatch(pkg, threat, rule)
	case "similarity":
		return tc.similarityMatch(pkg, threat, rule)
	default:
		return nil, fmt.Errorf("unknown matching rule type: %s", rule.Type)
	}
}

func (tc *ThreatCorrelator) exactMatch(pkg *types.Package, threat *ThreatIntelligence, rule *MatchingRule) (*ThreatMatch, error) {
	if pkg.Name == threat.PackageName && pkg.Type == threat.Ecosystem {
		return &ThreatMatch{
			ThreatID:        threat.ID,
			Source:          threat.Source,
			MatchType:       "exact",
			MatchConfidence: rule.Weight * threat.ConfidenceLevel,
			ThreatType:      threat.Type,
			Severity:        threat.Severity,
			Description:     threat.Description,
			FirstSeen:       threat.FirstSeen,
		}, nil
	}
	return nil, nil
}

func (tc *ThreatCorrelator) patternMatch(pkg *types.Package, threat *ThreatIntelligence, rule *MatchingRule) (*ThreatMatch, error) {
	for _, indicator := range threat.Indicators {
		if indicator.Type == "pattern" {
			matched, err := regexp.MatchString(indicator.Value, pkg.Name)
			if err != nil {
				return nil, err
			}
			if matched {
				confidence := rule.Weight * threat.ConfidenceLevel * indicator.Confidence
				return &ThreatMatch{
					ThreatID:        threat.ID,
					Source:          threat.Source,
					MatchType:       "pattern",
					MatchConfidence: confidence,
					ThreatType:      threat.Type,
					Severity:        threat.Severity,
					Description:     fmt.Sprintf("%s (pattern: %s)", threat.Description, indicator.Value),
					FirstSeen:       threat.FirstSeen,
				}, nil
			}
		}
	}
	return nil, nil
}

func (tc *ThreatCorrelator) similarityMatch(pkg *types.Package, threat *ThreatIntelligence, rule *MatchingRule) (*ThreatMatch, error) {
	similarity := tc.calculateStringSimilarity(pkg.Name, threat.PackageName)
	threshold := 0.8 // Default threshold

	if thresholdVal, ok := rule.Config["threshold"].(float64); ok {
		threshold = thresholdVal
	}

	if similarity > threshold {
		confidence := rule.Weight * threat.ConfidenceLevel * similarity
		return &ThreatMatch{
			ThreatID:        threat.ID,
			Source:          threat.Source,
			MatchType:       "similarity",
			MatchConfidence: confidence,
			ThreatType:      threat.Type,
			Severity:        threat.Severity,
			Description:     fmt.Sprintf("%s (similarity: %.2f)", threat.Description, similarity),
			FirstSeen:       threat.FirstSeen,
		}, nil
	}

	return nil, nil
}

func (tc *ThreatCorrelator) calculateOverallRisk(matches []ThreatMatch) (string, float64) {
	if len(matches) == 0 {
		return "none", 0.0
	}

	var totalScore float64
	var maxSeverityWeight float64
	severityCounts := make(map[string]int)

	for _, match := range matches {
		severityWeight := tc.severityWeights[match.Severity]
		totalScore += match.MatchConfidence * severityWeight
		severityCounts[match.Severity]++

		if severityWeight > maxSeverityWeight {
			maxSeverityWeight = severityWeight
		}
	}

	// Calculate average confidence score
	confidenceScore := totalScore / float64(len(matches))

	// Determine overall severity based on highest severity match
	overallSeverity := "low"
	for severity, weight := range tc.severityWeights {
		if weight == maxSeverityWeight && severityCounts[severity] > 0 {
			overallSeverity = severity
			break
		}
	}

	return overallSeverity, confidenceScore
}

func (tc *ThreatCorrelator) generateRecommendations(pkg *types.Package, matches []ThreatMatch, overallSeverity string) []string {
	var recommendations []string

	if len(matches) == 0 {
		recommendations = append(recommendations, "No known threats detected for this package")
		return recommendations
	}

	switch overallSeverity {
	case "critical":
		recommendations = append(recommendations, "CRITICAL: Do not use this package - known malicious activity detected")
		recommendations = append(recommendations, "Remove this package immediately from your dependencies")
		recommendations = append(recommendations, "Scan your system for potential compromise")
	case "high":
		recommendations = append(recommendations, "HIGH RISK: Avoid using this package")
		recommendations = append(recommendations, "Consider alternative packages with similar functionality")
		recommendations = append(recommendations, "If usage is necessary, implement additional security monitoring")
	case "medium":
		recommendations = append(recommendations, "MEDIUM RISK: Use with caution")
		recommendations = append(recommendations, "Monitor for updates and security advisories")
		recommendations = append(recommendations, "Consider pinning to a specific version")
	case "low":
		recommendations = append(recommendations, "LOW RISK: Monitor for updates")
		recommendations = append(recommendations, "Keep package updated to latest version")
	}

	// Add specific recommendations based on threat types
	threatTypes := make(map[string]bool)
	for _, match := range matches {
		threatTypes[match.ThreatType] = true
	}

	if threatTypes["typosquatting"] {
		recommendations = append(recommendations, "Verify package name spelling and official repository")
	}

	if threatTypes["malware"] {
		recommendations = append(recommendations, "Run antivirus scan on development environment")
	}

	if threatTypes["supply_chain"] {
		recommendations = append(recommendations, "Verify package integrity and maintainer reputation")
	}

	return recommendations
}

func (tc *ThreatCorrelator) calculateStringSimilarity(s1, s2 string) float64 {
	// Simple Levenshtein distance-based similarity
	// In a real implementation, you might use more sophisticated algorithms
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if s1 == s2 {
		return 1.0
	}

	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}

	if maxLen == 0 {
		return 1.0
	}

	distance := tc.levenshteinDistance(s1, s2)
	return 1.0 - float64(distance)/float64(maxLen)
}

func (tc *ThreatCorrelator) levenshteinDistance(s1, s2 string) int {
	len1, len2 := len(s1), len(s2)
	matrix := make([][]int, len1+1)

	for i := range matrix {
		matrix[i] = make([]int, len2+1)
		matrix[i][0] = i
	}

	for j := 0; j <= len2; j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len1][len2]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func (tc *ThreatCorrelator) removeDuplicateThreats(threats []ThreatIntelligence) []ThreatIntelligence {
	seen := make(map[string]bool)
	var unique []ThreatIntelligence

	for _, threat := range threats {
		if !seen[threat.ID] {
			seen[threat.ID] = true
			unique = append(unique, threat)
		}
	}

	return unique
}

func (tc *ThreatCorrelator) generateCacheKey(pkg *types.Package) string {
	return fmt.Sprintf("%s:%s:%s", pkg.Name, pkg.Type, pkg.Version)
}

func (tc *ThreatCorrelator) getCachedResult(key string) *ThreatCorrelationResult {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if cached, exists := tc.cache[key]; exists {
		if time.Since(cached.Timestamp) < tc.cacheExpiry {
			return cached.Result
		}
		// Remove expired entry
		delete(tc.cache, key)
	}

	return nil
}

func (tc *ThreatCorrelator) cacheResult(key string, result *ThreatCorrelationResult) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache[key] = &CachedCorrelation{
		Result:    result,
		Timestamp: time.Now(),
	}
}

func (tc *ThreatCorrelator) startCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(tc.cacheExpiry)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tc.cleanupExpiredCache()
		}
	}
}

func (tc *ThreatCorrelator) cleanupExpiredCache() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	for key, cached := range tc.cache {
		if now.Sub(cached.Timestamp) > tc.cacheExpiry {
			delete(tc.cache, key)
		}
	}
}

func (tc *ThreatCorrelator) initializeMatchingRules() {
	tc.matchingRules = []MatchingRule{
		{
			Name:    "exact_match",
			Type:    "exact",
			Weight:  1.0,
			Enabled: true,
		},
		{
			Name:    "pattern_match",
			Type:    "pattern",
			Weight:  0.8,
			Enabled: true,
		},
		{
			Name:    "similarity_match",
			Type:    "similarity",
			Weight:  0.6,
			Enabled: true,
			Config: map[string]interface{}{
				"threshold": 0.8,
			},
		},
	}

	// Initialize matcher functions
	for i := range tc.matchingRules {
		tc.initializeMatcherFunc(&tc.matchingRules[i])
	}
}

func (tc *ThreatCorrelator) initializeMatcherFunc(rule *MatchingRule) {
	// Custom matcher functions can be set here
	// For now, we use the default logic in applyMatchingRule
	rule.Matcher = nil
}