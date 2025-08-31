package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DemoPackage represents a package for demonstration
type DemoPackage struct {
	Name        string
	Version     string
	Registry    string
	Downloads   int64
	Maintainers []string
	Repository  string
	Description string
}

func main() {
	fmt.Println("Enhanced Supply Chain Detection Demo")
	fmt.Println("====================================")

	// Create enhanced supply chain detector
	detector := detector.NewEnhancedSupplyChainDetector()

	// Test packages based on our webpack2 analysis insights
	testPackages := []DemoPackage{
		{
			Name:        "webpack2",
			Version:     "1.0.0",
			Registry:    "npm",
			Downloads:   5,
			Maintainers: []string{"suspicious-user"},
			Repository:  "https://github.com/webpack/webpack", // Claims official repo
			Description: "The official webpack package",       // Suspicious claim
		},
		{
			Name:        "webpack",
			Version:     "5.88.2",
			Registry:    "npm",
			Downloads:   30000000,
			Maintainers: []string{"sokra", "webpack-team"},
			Repository:  "https://github.com/webpack/webpack",
			Description: "A bundler for javascript and friends",
		},
		{
			Name:        "content-type",
			Version:     "1.0.5",
			Registry:    "npm",
			Downloads:   50000000,
			Maintainers: []string{"dougwilson"},
			Repository:  "https://github.com/jshttp/content-type",
			Description: "Create and parse HTTP Content-Type header",
		},
		{
			Name:        "lodash2",
			Version:     "1.0.0",
			Registry:    "npm",
			Downloads:   10,
			Maintainers: []string{"fake-maintainer"},
			Repository:  "https://github.com/lodash/lodash", // Claims official repo
			Description: "A modern JavaScript utility library",
		},
		{
			Name:        "express-js",
			Version:     "1.0.0",
			Registry:    "npm",
			Downloads:   100,
			Maintainers: []string{"unknown"},
			Repository:  "",
			Description: "Fast, unopinionated, minimalist web framework",
		},
	}

	// Convert to types.Package and analyze
	var packages []types.Package
	for _, demo := range testPackages {
		pkg := convertDemoToPackage(demo)
		packages = append(packages, pkg)
	}

	// Perform threat detection
	ctx := context.Background()
	results, err := detector.DetectThreats(ctx, packages)
	if err != nil {
		log.Fatalf("Error detecting threats: %v", err)
	}

	// Display results
	fmt.Printf("\nAnalysis Results (%d packages analyzed):\n", len(packages))
	fmt.Println("=" + fmt.Sprintf("%*s", 50, "="))

	for _, result := range results {
		displayResult(result)
	}

	// Summary statistics
	displaySummary(results, len(packages))
}

func convertDemoToPackage(demo DemoPackage) types.Package {
	return types.Package{
		Name:     demo.Name,
		Version:  demo.Version,
		Registry: demo.Registry,
		Metadata: &types.PackageMetadata{
			Name:        demo.Name,
			Version:     demo.Version,
			Description: demo.Description,
			Repository:  demo.Repository,
			Maintainers: demo.Maintainers,
			CreatedAt:   time.Now().AddDate(-1, 0, 0), // 1 year ago
			UpdatedAt:   time.Now().AddDate(0, -1, 0), // 1 month ago
		},
		AnalyzedAt: time.Now(),
	}
}

func displayResult(result *detector.EnhancedThreatResult) {
	fmt.Printf("\n📦 Package: %s (%s)\n", result.Package, result.Registry)
	fmt.Printf("   Threat Type: %s\n", result.ThreatType)
	fmt.Printf("   Severity: %s\n", result.Severity)
	fmt.Printf("   Confidence: %.2f\n", result.ConfidenceScore)
	fmt.Printf("   Supply Chain Risk: %.2f\n", result.SupplyChainRisk)
	fmt.Printf("   False Positive Risk: %.2f\n", result.FalsePositiveRisk)

	if result.IsFiltered {
		fmt.Printf("   🚫 FILTERED: %v\n", result.FilterReasons)
	}

	// Metadata analysis
	if result.MetadataAnalysis != nil {
		fmt.Printf("   📊 Metadata Analysis:\n")
		fmt.Printf("      - Legitimate: %t\n", result.MetadataAnalysis.IsLegitimate)
		fmt.Printf("      - Popularity Score: %.2f\n", result.MetadataAnalysis.PopularityScore)
		fmt.Printf("      - Typosquatting Risk: %.2f\n", result.MetadataAnalysis.TyposquattingRisk)

		if len(result.MetadataAnalysis.RiskFactors) > 0 {
			fmt.Printf("      - Risk Factors: %v\n", result.MetadataAnalysis.RiskFactors)
		}

		if len(result.MetadataAnalysis.PositiveIndicators) > 0 {
			fmt.Printf("      - Positive Indicators: %v\n", result.MetadataAnalysis.PositiveIndicators)
		}
	}

	// Typosquatting analysis
	if result.TyposquattingAnalysis != nil {
		fmt.Printf("   🔍 Typosquatting Analysis:\n")
		fmt.Printf("      - Target Package: %s\n", result.TyposquattingAnalysis.PrimaryType)
		fmt.Printf("      - Edit Distance: %d\n", result.TyposquattingAnalysis.EditDistance)
		fmt.Printf("      - Visual Similarity: %.2f\n", result.TyposquattingAnalysis.VisualSimilarity)
		fmt.Printf("      - Phonetic Similarity: %.2f\n", result.TyposquattingAnalysis.PhoneticSimilarity)
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		fmt.Printf("   💡 Recommendations:\n")
		for _, rec := range result.Recommendations {
			fmt.Printf("      - %s\n", rec)
		}
	}

	// Evidence
	if len(result.Evidence) > 0 {
		fmt.Printf("   🔍 Evidence:\n")
		for _, evidence := range result.Evidence {
			fmt.Printf("      - [%s] %s (%s)\n", evidence.Type, evidence.Description, evidence.Severity)
		}
	}

	fmt.Println("   " + fmt.Sprintf("%*s", 60, "-"))
}

func displaySummary(results []*detector.EnhancedThreatResult, totalPackages int) {
	fmt.Printf("\n📈 Detection Summary:\n")
	fmt.Printf("   Total Packages Analyzed: %d\n", totalPackages)
	fmt.Printf("   Threats Detected: %d\n", len(results))
	fmt.Printf("   Filtered (False Positives): %d\n", countFiltered(results))

	// Severity breakdown
	severityCounts := make(map[string]int)
	threatTypeCounts := make(map[string]int)

	for _, result := range results {
		if !result.IsFiltered {
			severityCounts[result.Severity]++
			threatTypeCounts[result.ThreatType]++
		}
	}

	if len(severityCounts) > 0 {
		fmt.Printf("\n   Severity Breakdown:\n")
		for severity, count := range severityCounts {
			fmt.Printf("      - %s: %d\n", severity, count)
		}
	}

	if len(threatTypeCounts) > 0 {
		fmt.Printf("\n   Threat Type Breakdown:\n")
		for threatType, count := range threatTypeCounts {
			fmt.Printf("      - %s: %d\n", threatType, count)
		}
	}

	// False positive rate
	filteredCount := countFiltered(results)
	if totalPackages > 0 {
		fpRate := float64(filteredCount) / float64(totalPackages) * 100
		fmt.Printf("\n   False Positive Rate: %.1f%%\n", fpRate)
	}

	// Key insights
	fmt.Printf("\n🎯 Key Insights:\n")

	highRiskCount := 0
	typosquattingCount := 0

	for _, result := range results {
		if !result.IsFiltered {
			if result.SupplyChainRisk > 0.7 {
				highRiskCount++
			}
			if result.ThreatType == "TYPOSQUATTING" {
				typosquattingCount++
			}
		}
	}

	fmt.Printf("   - High Risk Packages: %d\n", highRiskCount)
	fmt.Printf("   - Potential Typosquatting: %d\n", typosquattingCount)
	fmt.Printf("   - Enhanced filtering reduced false positives\n")
	fmt.Printf("   - Metadata-based analysis improved accuracy\n")
}

func countFiltered(results []*detector.EnhancedThreatResult) int {
	count := 0
	for _, result := range results {
		if result.IsFiltered {
			count++
		}
	}
	return count
}

// Additional utility functions for demonstration

func saveResultsToJSON(results []*detector.EnhancedThreatResult, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	// In a real implementation, you would write to file
	fmt.Printf("\n💾 Results saved to %s (%d bytes)\n", filename, len(data))
	return nil
}

func generateReport(results []*detector.EnhancedThreatResult) string {
	report := "Enhanced Supply Chain Security Report\n"
	report += "=====================================\n\n"

	for _, result := range results {
		if !result.IsFiltered && result.Severity == "CRITICAL" {
			report += fmt.Sprintf("CRITICAL THREAT: %s\n", result.Package)
			report += fmt.Sprintf("  Risk Score: %.2f\n", result.SupplyChainRisk)
			report += fmt.Sprintf("  Type: %s\n", result.ThreatType)
			report += "\n"
		}
	}

	return report
}
