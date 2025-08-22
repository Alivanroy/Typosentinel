package ml

import (
	"math"
	"strings"
)

// calculateLengthDifferencePenalty applies penalty based on significant length differences
func (a *MLAnalyzer) calculateLengthDifferencePenalty(name1, name2 string) float64 {
	lengthDiff := math.Abs(float64(len(name1) - len(name2)))
	maxLength := math.Max(float64(len(name1)), float64(len(name2)))
	
	if maxLength == 0 {
		return 1.0
	}
	
	// Calculate length difference ratio
	lengthRatio := lengthDiff / maxLength
	
	// Apply penalty for significant length differences
	if lengthRatio > 0.5 {
		return 0.3 // Heavy penalty for very different lengths
	} else if lengthRatio > 0.3 {
		return 0.6 // Moderate penalty for moderately different lengths
	} else if lengthRatio > 0.1 {
		return 0.8 // Light penalty for slightly different lengths
	}
	
	return 1.0 // No penalty for similar lengths
}

// calculateSemanticContextPenalty applies penalty for semantically unrelated packages
func (a *MLAnalyzer) calculateSemanticContextPenalty(name1, name2 string) float64 {
	// Define semantic categories
	webFrameworks := []string{"react", "vue", "angular", "express", "flask", "django"}
	paymentServices := []string{"stripe", "paypal", "square", "braintree"}
	buildTools := []string{"webpack", "babel", "gulp", "grunt", "rollup"}
	testingTools := []string{"jest", "mocha", "chai", "jasmine", "karma"}
	languageTools := []string{"typescript", "coffeescript", "babel", "eslint"}
	cloudServices := []string{"aws-sdk", "azure", "gcp", "twilio"}
	
	categories := [][]string{webFrameworks, paymentServices, buildTools, testingTools, languageTools, cloudServices}
	
	// Check if both packages belong to the same semantic category
	for _, category := range categories {
		name1InCategory := false
		name2InCategory := false
		
		for _, pkg := range category {
			if strings.Contains(strings.ToLower(name1), pkg) {
				name1InCategory = true
			}
			if strings.Contains(strings.ToLower(name2), pkg) {
				name2InCategory = true
			}
		}
		
		// If both are in the same category, no penalty
		if name1InCategory && name2InCategory {
			return 1.0
		}
		
		// If one is in a category but the other isn't, apply penalty
		if name1InCategory || name2InCategory {
			return 0.5
		}
	}
	
	// Default: no strong semantic relationship detected
	return 0.8
}

// hasSignificantLengthDifference checks if two package names have significantly different lengths
func (a *MLAnalyzer) hasSignificantLengthDifference(name1, name2 string) bool {
	lengthDiff := math.Abs(float64(len(name1) - len(name2)))
	maxLength := math.Max(float64(len(name1)), float64(len(name2)))
	
	if maxLength == 0 {
		return false
	}
	
	// Consider significant if length difference is more than 40% of the longer name
	return (lengthDiff / maxLength) > 0.4
}

// hasUnrelatedSemanticContext checks if two packages are semantically unrelated
func (a *MLAnalyzer) hasUnrelatedSemanticContext(name1, name2 string) bool {
	// Check for obvious semantic mismatches
	paymentTerms := []string{"pay", "stripe", "payment", "billing", "invoice"}
	languageTerms := []string{"script", "type", "lang", "compile"}
	frameworkTerms := []string{"react", "vue", "angular", "framework"}
	testingTerms := []string{"test", "spec", "mock", "assert"}
	
	termSets := [][]string{paymentTerms, languageTerms, frameworkTerms, testingTerms}
	
	name1Lower := strings.ToLower(name1)
	name2Lower := strings.ToLower(name2)
	
	for _, termSet := range termSets {
		name1HasTerms := false
		name2HasTerms := false
		
		for _, term := range termSet {
			if strings.Contains(name1Lower, term) {
				name1HasTerms = true
			}
			if strings.Contains(name2Lower, term) {
				name2HasTerms = true
			}
		}
		
		// If one has terms from a category but the other doesn't, they're unrelated
		if name1HasTerms != name2HasTerms {
			return true
		}
	}
	
	return false
}