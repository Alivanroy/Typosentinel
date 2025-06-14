package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/typosentinel/typosentinel/pkg/types"
)

// Analyzer provides package analysis capabilities
type Analyzer struct {
	// Add configuration fields as needed
}

// New creates a new analyzer instance
func New() *Analyzer {
	return &Analyzer{}
}

// AnalyzePackage performs comprehensive analysis of a package
func (a *Analyzer) AnalyzePackage(ctx context.Context, pkg *types.Dependency) (*types.AnalysisResult, error) {
	result := &types.AnalysisResult{
		ID:        fmt.Sprintf("analysis_%d", time.Now().Unix()),
		Package:   pkg,
		Timestamp: time.Now(),
		Threats:   []types.Threat{},
		Metadata:  make(map[string]interface{}),
	}

	// Basic typosquatting detection
	if threats := a.detectTyposquatting(pkg); len(threats) > 0 {
		result.Threats = append(result.Threats, threats...)
	}

	// Set overall risk level
	result.RiskLevel = a.calculateRiskLevel(result.Threats)

	return result, nil
}

// detectTyposquatting performs basic typosquatting detection
func (a *Analyzer) detectTyposquatting(pkg *types.Dependency) []types.Threat {
	var threats []types.Threat

	// Popular packages to check against
	popularPackages := []string{
		"numpy", "pandas", "requests", "flask", "django", "tensorflow",
		"react", "angular", "vue", "express", "lodash", "axios",
		"jquery", "bootstrap", "moment", "chalk", "commander",
	}

	for _, popular := range popularPackages {
		if similarity := a.calculateSimilarity(pkg.Name, popular); similarity > 0.7 && pkg.Name != popular {
			threats = append(threats, types.Threat{
				ID:          fmt.Sprintf("typo-%s-%d", pkg.Name, len(threats)),
				Package:     pkg.Name,
				Registry:    "npm", // default registry
				Type:        types.ThreatTypeTyposquatting,
				Severity:    types.SeverityHigh,
				Confidence:  similarity,
				Description: fmt.Sprintf("Potential typosquatting: %s is similar to popular package %s", pkg.Name, popular),
				SimilarTo:   popular,
				Evidence: []types.Evidence{
					{
						Type:        "similarity",
						Description: "Levenshtein distance similarity score",
						Value:       similarity,
						Score:       similarity,
					},
				},
				DetectedAt:      time.Now(),
				DetectionMethod: "levenshtein_similarity",
			})
		}
	}

	return threats
}

// calculateSimilarity calculates similarity between two strings
func (a *Analyzer) calculateSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Simple Levenshtein distance-based similarity
	dist := levenshteinDistance(s1, s2)
	maxLen := max(len(s1), len(s2))
	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - float64(dist)/float64(maxLen)
}

// calculateRiskLevel determines overall risk level based on threats
func (a *Analyzer) calculateRiskLevel(threats []types.Threat) types.Severity {
	if len(threats) == 0 {
		return types.SeverityLow
	}

	highestSeverity := types.SeverityLow
	for _, threat := range threats {
		if threat.Severity > highestSeverity {
			highestSeverity = threat.Severity
		}
	}

	return highestSeverity
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func levenshteinDistance(s1, s2 string) int {
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
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// Helper functions
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}