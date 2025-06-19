package main

import (
	"context"
	"fmt"
	"typosentinel/internal/config"
	"typosentinel/internal/ml"
	"typosentinel/pkg/types"
)

// Helper functions for debugging
func levenshteinDistance(s1, s2 string) int {
	m, n := len(s1), len(s2)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	
	for i := 0; i <= m; i++ {
		dp[i][0] = i
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = j
	}
	
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
			}
		}
	}
	
	return dp[m][n]
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	// Initialize ML analyzer
	analyzer := ml.NewMLAnalyzer(config.MLAnalysisConfig{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
	})

	// Test suspicious package (should be HIGH risk)
	suspiciousPkg := &types.Package{
		Name:    "github.com/gin-gonic/ginn",
		Version: "v1.9.0",
		Metadata: &types.PackageMetadata{
			Name:        "github.com/gin-gonic/ginn",
			Version:     "v1.9.0",
			Description: "Gin is a HTTP web framework written in Go (Golang). It features a Martini-like API with much better performance.",
		},
	}

	// Test legitimate package (should be LOW risk)
	legitPkg := &types.Package{
		Name:    "github.com/gin-gonic/gin",
		Version: "v1.9.1",
		Metadata: &types.PackageMetadata{
			Name:        "github.com/gin-gonic/gin",
			Version:     "v1.9.1",
			Description: "Gin is a HTTP web framework written in Go (Golang). It features a Martini-like API with much better performance -- up to 40 times faster.",
		},
	}

	ctx := context.Background()

	// Debug: Test similarity calculation directly
	fmt.Println("=== Debug Similarity Calculation ===")
	pkg1 := "github.com/gin-gonic/ginn"
	pkg2 := "github.com/gin-gonic/gin"
	fmt.Printf("Comparing: %s vs %s\n", pkg1, pkg2)
	
	// Manual similarity test
	distance := levenshteinDistance(pkg1, pkg2)
	maxLen := max(len(pkg1), len(pkg2))
	similarity := 1.0 - float64(distance)/float64(maxLen)
	fmt.Printf("Levenshtein distance: %d\n", distance)
	fmt.Printf("Max length: %d\n", maxLen)
	fmt.Printf("Calculated similarity: %.3f\n", similarity)
	fmt.Println()

	// Analyze suspicious package
	fmt.Println("=== Suspicious Package Analysis ===")
	result1, err := analyzer.Analyze(ctx, suspiciousPkg)
	if err != nil {
		fmt.Printf("Error analyzing suspicious package: %v\n", err)
	} else {
		fmt.Printf("Package: %s\n", suspiciousPkg.Name)
		fmt.Printf("Risk Level: %s\n", result1.RiskAssessment.OverallRisk)
		fmt.Printf("Risk Score: %.3f\n", result1.RiskAssessment.RiskScore)
		fmt.Printf("Expected: HIGH/0.91\n")
		fmt.Printf("Risk Factors: %v\n", result1.RiskAssessment.RiskFactors)
	}

	// Analyze legitimate package
	fmt.Println("\n=== Legitimate Package Analysis ===")
	result2, err := analyzer.Analyze(ctx, legitPkg)
	if err != nil {
		fmt.Printf("Error analyzing legitimate package: %v\n", err)
	} else {
		fmt.Printf("Package: %s\n", legitPkg.Name)
		fmt.Printf("Risk Level: %s\n", result2.RiskAssessment.OverallRisk)
		fmt.Printf("Risk Score: %.3f\n", result2.RiskAssessment.RiskScore)
		fmt.Printf("Expected: LOW/0.05\n")
		fmt.Printf("Risk Factors: %v\n", result2.RiskAssessment.RiskFactors)
	}
}