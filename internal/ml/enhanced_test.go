package ml

import (
	"context"
	"testing"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestEnhancedMLAlgorithms(t *testing.T) {
	config := Config{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
		ModelPath:           "models/",
		BatchSize:           10,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  true,
		GPUAcceleration:     false,
	}

	enhanced := NewEnhancedMLAlgorithms(config)

	t.Run("TestAdvancedSimilarityAnalysis", func(t *testing.T) {
		pkg := &types.Package{
			Name:    "expres", // Typosquatting of "express"
			Version: "1.0.0",
			Metadata: &types.PackageMetadata{
				Description: "A web framework",
				Author:      "test-author",
			},
		}

		// Use a more comprehensive list that includes express
		popularPackages := []string{
			"express", "lodash", "react", "angular", "vue", "webpack", "babel", 
			"eslint", "prettier", "typescript", "axios", "moment", "underscore", 
			"jquery", "bootstrap", "chalk", "commander", "debug", "request", "async",
		}
		result := enhanced.AdvancedSimilarityAnalysis(pkg, popularPackages)

		if result.PackageName != "expres" {
			t.Errorf("Expected package name 'expres', got '%s'", result.PackageName)
		}

		if len(result.SimilarPackages) == 0 {
			t.Error("Expected similar packages to be found")
		}

		// Should detect high similarity with "express"
		found := false
		for _, similar := range result.SimilarPackages {
			if similar.Name == "express" && similar.SimilarityMetrics.OverallScore > 0.7 {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected high similarity with 'express' package")
		}

		if !result.IsTyposquatting {
			t.Error("Expected typosquatting to be detected")
		}
	})

	t.Run("TestAdvancedMaliciousDetection", func(t *testing.T) {
		ctx := context.Background()
		
		// Test suspicious package
		suspiciousPkg := &types.Package{
			Name:    "test123",
			Version: "0.0.1",
			Metadata: &types.PackageMetadata{
				Description: "test package",
				Author:      "user123",
			},
		}

		result := enhanced.AdvancedMaliciousDetection(ctx, suspiciousPkg)

		if result.PackageName != "test123" {
			t.Errorf("Expected package name 'test123', got '%s'", result.PackageName)
		}

		if result.MaliciousScore == 0 {
			t.Error("Expected some malicious score for suspicious package")
		}

		if len(result.Indicators) == 0 {
			t.Error("Expected malicious indicators to be found")
		}

		// Test legitimate package
		legitimatePkg := &types.Package{
			Name:    "my-awesome-library",
			Version: "2.1.0",
			Metadata: &types.PackageMetadata{
				Description: "A well-documented library for data processing with comprehensive features",
				Author:      "john.doe@example.com",
			},
		}

		legitimateResult := enhanced.AdvancedMaliciousDetection(ctx, legitimatePkg)
		
		if legitimateResult.MaliciousScore > 0.5 {
			t.Error("Expected low malicious score for legitimate package")
		}
	})

	t.Run("TestSimilarityMetrics", func(t *testing.T) {
		metrics := enhanced.calculateMultiAlgorithmSimilarity("express", "expres")

		if metrics.LevenshteinSimilarity <= 0.5 {
			t.Error("Expected high Levenshtein similarity")
		}

		if metrics.JaroWinklerSimilarity <= 0.5 {
			t.Error("Expected high Jaro-Winkler similarity")
		}

		if metrics.OverallScore <= 0.5 {
			t.Error("Expected high overall similarity score")
		}

		// Test dissimilar strings
		dissimilarMetrics := enhanced.calculateMultiAlgorithmSimilarity("express", "completely-different")
		if dissimilarMetrics.OverallScore > 0.3 {
			t.Error("Expected low similarity for dissimilar strings")
		}
	})

	t.Run("TestHelperFunctions", func(t *testing.T) {
		// Test Levenshtein distance
		distance := enhanced.levenshteinDistance("express", "expres")
		if distance != 1 {
			t.Errorf("Expected Levenshtein distance of 1, got %d", distance)
		}

		// Test Jaro-Winkler similarity
		similarity := enhanced.jaroWinklerSimilarity("express", "expres")
		if similarity <= 0.8 {
			t.Errorf("Expected high Jaro-Winkler similarity, got %f", similarity)
		}

		// Test Jaccard similarity
		jaccard := enhanced.jaccardSimilarity("express", "expres")
		if jaccard <= 0.7 {
			t.Errorf("Expected high Jaccard similarity, got %f", jaccard)
		}

		// Test phonetic similarity
		phonetic := enhanced.phoneticSimilarity("express", "expres")
		if phonetic <= 0.5 {
			t.Errorf("Expected reasonable phonetic similarity, got %f", phonetic)
		}
	})

	t.Run("TestTyposquattingDetection", func(t *testing.T) {
		// Test character substitution
		hasSubstitution := enhanced.hasCharacterSubstitutions("express", "3xpress")
		if !hasSubstitution {
			t.Error("Expected character substitution to be detected")
		}

		// Test insertion/deletion
		hasInsertion := enhanced.hasInsertionDeletionPatterns("express", "expres")
		if !hasInsertion {
			t.Error("Expected insertion/deletion pattern to be detected")
		}

		// Test typosquatting risk assessment
		risk := enhanced.assessTyposquattingRisk("expres", "express")
		if risk <= 0.3 {
			t.Errorf("Expected higher typosquatting risk, got %f", risk)
		}
	})

	t.Run("TestSuspiciousPatternDetection", func(t *testing.T) {
		// Test suspicious naming
		if !enhanced.hasSuspiciousNaming("test123") {
			t.Error("Expected 'test123' to be flagged as suspicious")
		}

		if enhanced.hasSuspiciousNaming("my-awesome-library") {
			t.Error("Expected 'my-awesome-library' to not be flagged as suspicious")
		}

		// Test suspicious description
		if !enhanced.hasSuspiciousDescription("test") {
			t.Error("Expected short description to be flagged as suspicious")
		}

		if !enhanced.hasSuspiciousDescription("This is a hack tool") {
			t.Error("Expected description with 'hack' to be flagged as suspicious")
		}

		// Test suspicious author
		if !enhanced.hasSuspiciousAuthor("user123") {
			t.Error("Expected 'user123' to be flagged as suspicious author")
		}

		if enhanced.hasSuspiciousAuthor("john.doe@example.com") {
			t.Error("Expected 'john.doe@example.com' to not be flagged as suspicious")
		}
	})

	t.Run("TestConfidenceCalculation", func(t *testing.T) {
		// Test high confidence scenario (consistent high scores)
		metrics := SimilarityMetrics{
			LevenshteinSimilarity: 0.9,
			JaroWinklerSimilarity: 0.85,
			CosineSimilarity:      0.88,
			JaccardSimilarity:     0.87,
			OverallScore:          0.875,
		}

		confidence := enhanced.calculateConfidenceScore(metrics)
		if confidence <= 0.7 {
			t.Errorf("Expected high confidence for consistent scores, got %f", confidence)
		}

		// Test low confidence scenario (inconsistent scores)
		inconsistentMetrics := SimilarityMetrics{
			LevenshteinSimilarity: 0.9,
			JaroWinklerSimilarity: 0.2,
			CosineSimilarity:      0.8,
			JaccardSimilarity:     0.1,
			OverallScore:          0.5,
		}

		lowConfidence := enhanced.calculateConfidenceScore(inconsistentMetrics)
		if lowConfidence >= confidence {
			t.Error("Expected lower confidence for inconsistent scores")
		}
	})
}

func TestEnhancedMLIntegration(t *testing.T) {
	// Test integration with main ML analyzer
	config := DefaultConfig()
	config.Enabled = true

	analyzer := NewMLAnalyzer(config)
	if analyzer.EnhancedAlgorithms == nil {
		t.Error("Expected enhanced algorithms to be initialized")
	}

	ctx := context.Background()
	pkg := &types.Package{
		Name:    "expres",
		Version: "1.0.0",
		Metadata: &types.PackageMetadata{
			Description: "A web framework",
			Author:      "test-author",
		},
	}

	result, err := analyzer.Analyze(ctx, pkg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected analysis result")
	}

	if result.SimilarityScore == 0 {
		t.Error("Expected similarity score to be calculated")
	}

	if len(result.SimilarPackages) == 0 {
		t.Error("Expected similar packages to be found")
	}

	if result.TyposquattingScore == 0 {
		t.Error("Expected typosquatting score to be calculated")
	}
}

func BenchmarkEnhancedSimilarityAnalysis(b *testing.B) {
	config := Config{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
	}

	enhanced := NewEnhancedMLAlgorithms(config)
	pkg := &types.Package{
		Name:    "expres",
		Version: "1.0.0",
		Metadata: &types.PackageMetadata{
			Description: "A web framework",
			Author:      "test-author",
		},
	}

	popularPackages := []string{"express", "lodash", "react", "angular", "vue", "webpack", "babel"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enhanced.AdvancedSimilarityAnalysis(pkg, popularPackages)
	}
}

func BenchmarkEnhancedMaliciousDetection(b *testing.B) {
	config := Config{
		Enabled:             true,
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
	}

	enhanced := NewEnhancedMLAlgorithms(config)
	ctx := context.Background()
	pkg := &types.Package{
		Name:    "test123",
		Version: "0.0.1",
		Metadata: &types.PackageMetadata{
			Description: "test package",
			Author:      "user123",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enhanced.AdvancedMaliciousDetection(ctx, pkg)
	}
}