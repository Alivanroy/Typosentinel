package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/typosentinel/typosentinel/internal/ml"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// PackageAnalysis represents detailed analysis of a specific package
type PackageAnalysis struct {
	Package        *types.Package                 `json:"package"`
	Threats        []*types.Threat                `json:"threats"`
	SimilarPackages []SimilarPackage              `json:"similar_packages,omitempty"`
	MLAnalysis     *MLPackageAnalysis             `json:"ml_analysis,omitempty"`
	Metadata       map[string]interface{}         `json:"metadata,omitempty"`
	AnalyzedAt     time.Time                      `json:"analyzed_at"`
}

// SimilarPackage represents a package similar to the analyzed one
type SimilarPackage struct {
	Name       string  `json:"name"`
	Registry   string  `json:"registry"`
	Similarity float64 `json:"similarity"`
	Reason     string  `json:"reason"`
}

// MLPackageAnalysis represents ML analysis results for a package
type MLPackageAnalysis struct {
	MaliciousScore     float64                `json:"malicious_score"`
	MaliciousConfidence float64               `json:"malicious_confidence"`
	IsMalicious        bool                   `json:"is_malicious"`
	Reasons            []string               `json:"reasons"`
	SimilarityResults  []ml.SimilarityResult  `json:"similarity_results,omitempty"`
	Features           map[string]interface{} `json:"features,omitempty"`
	ModelInfo          string                 `json:"model_info"`
}

// ReportSummary represents a summary of the entire report
type ReportSummary struct {
	TotalPackages       int                    `json:"total_packages"`
	AnalyzedPackages    int                    `json:"analyzed_packages"`
	ThreatsFound        int                    `json:"threats_found"`
	HighRiskPackages    int                    `json:"high_risk_packages"`
	MediumRiskPackages  int                    `json:"medium_risk_packages"`
	LowRiskPackages     int                    `json:"low_risk_packages"`
	MLAnalysisEnabled   bool                   `json:"ml_analysis_enabled"`
	MaliciousPackages   int                    `json:"malicious_packages"`
	SuspiciousPackages  int                    `json:"suspicious_packages"`
	Recommendations     []string               `json:"recommendations"`
	GeneratedAt         time.Time              `json:"generated_at"`
}

// performMLAnalysis performs ML analysis on a list of packages
func performMLAnalysis(packages []*types.Package) map[string]interface{} {
	if !mlEnabled {
		return nil
	}

	apiKey := os.Getenv("TYPOSENTINEL_API_KEY")
	if apiKey == "" {
		apiKey = "dev-key-123" // Default development key
	}
	mlClient := ml.NewClient(mlURL, apiKey)
	ctx := context.Background()

	results := make(map[string]interface{})
	results["analyzed_packages"] = make([]map[string]interface{}, 0)
	results["summary"] = make(map[string]interface{})

	maliciousCount := 0
	suspiciousCount := 0

	for _, pkg := range packages {
		if pkg == nil {
			continue
		}

		packageResult := make(map[string]interface{})
		packageResult["name"] = pkg.Name
		packageResult["version"] = pkg.Version
		packageResult["registry"] = pkg.Registry

		// Check for malicious packages
		maliciousResp, err := mlClient.CheckMaliciousPackage(ctx, pkg.Name, pkg.Registry, pkg.Version)
		if err == nil {
			packageResult["malicious_analysis"] = maliciousResp
			if maliciousResp.IsMalicious {
				maliciousCount++
			} else if maliciousResp.Score > 0.5 {
				suspiciousCount++
			}
		} else {
			packageResult["malicious_analysis_error"] = err.Error()
		}

		// Find similar packages
		similarityResp, err := mlClient.FindSimilarPackages(ctx, pkg.Name, pkg.Registry, similarityK, threshold)
		if err == nil {
			packageResult["similarity_analysis"] = similarityResp
		} else {
			packageResult["similarity_analysis_error"] = err.Error()
		}

		results["analyzed_packages"] = append(results["analyzed_packages"].([]map[string]interface{}), packageResult)
	}

	// Add summary
	summary := map[string]interface{}{
		"total_packages":     len(packages),
		"malicious_packages": maliciousCount,
		"suspicious_packages": suspiciousCount,
		"analysis_timestamp": time.Now(),
	}
	results["summary"] = summary

	return results
}

// analyzeSpecificPackage analyzes a specific package with detailed information
func analyzeSpecificPackage(packageName, registry string, mlClient *ml.Client) *PackageAnalysis {
	analysis := &PackageAnalysis{
		Package: &types.Package{
			Name:     packageName,
			Registry: registry,
		},
		Threats:    make([]*types.Threat, 0),
		Metadata:   make(map[string]interface{}),
		AnalyzedAt: time.Now(),
	}

	if mlClient != nil {
		ctx := context.Background()

		// Perform ML analysis
		mlAnalysis := &MLPackageAnalysis{}

		// Check for malicious packages
		maliciousResp, err := mlClient.CheckMaliciousPackage(ctx, packageName, registry, "")
		if err == nil {
			mlAnalysis.MaliciousScore = maliciousResp.Score
			mlAnalysis.MaliciousConfidence = maliciousResp.Confidence
			mlAnalysis.IsMalicious = maliciousResp.IsMalicious
			mlAnalysis.Reasons = maliciousResp.Reasons
			mlAnalysis.Features = maliciousResp.Features
			mlAnalysis.ModelInfo = maliciousResp.Model
		}

		// Find similar packages
		similarityResp, err := mlClient.FindSimilarPackages(ctx, packageName, registry, similarityK, threshold)
		if err == nil {
			mlAnalysis.SimilarityResults = similarityResp.Results
			
			// Convert to SimilarPackage format
			for _, result := range similarityResp.Results {
				similar := SimilarPackage{
					Name:       result.PackageName,
					Registry:   result.Registry,
					Similarity: result.Score,
					Reason:     "ML similarity analysis",
				}
				analysis.SimilarPackages = append(analysis.SimilarPackages, similar)
			}
		}

		analysis.MLAnalysis = mlAnalysis
	}

	return analysis
}

// generateFullReport generates a comprehensive report
func generateFullReport(result *types.ScanResult, mlResults map[string]interface{}) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    TYPOSENTINEL COMPREHENSIVE REPORT")
	fmt.Println(strings.Repeat("=", 80))

	// Project Information
	fmt.Printf("\nProject Information:\n")
	fmt.Printf("  Target: %s\n", result.Target)
	fmt.Printf("  Type: %s\n", result.Type)
	fmt.Printf("  Scan Duration: %v\n", result.Duration)
	fmt.Printf("  Generated: %s\n", result.CreatedAt.Format(time.RFC3339))

	// Summary
	fmt.Printf("\nScan Summary:\n")
	if result.Summary != nil {
		fmt.Printf("  Total Packages: %d\n", result.Summary.TotalPackages)
		fmt.Printf("  Threats Found: %d\n", result.Summary.ThreatsFound)
		fmt.Printf("  Critical: %d\n", result.Summary.CriticalThreats)
		fmt.Printf("  High: %d\n", result.Summary.HighThreats)
		fmt.Printf("  Medium: %d\n", result.Summary.MediumThreats)
		fmt.Printf("  Low: %d\n", result.Summary.LowThreats)
	}

	// ML Analysis Summary
	if mlResults != nil {
		fmt.Printf("\nML Analysis Summary:\n")
		if summary, ok := mlResults["summary"].(map[string]interface{}); ok {
			if malicious, ok := summary["malicious_packages"].(int); ok {
				fmt.Printf("  Malicious Packages: %d\n", malicious)
			}
			if suspicious, ok := summary["suspicious_packages"].(int); ok {
				fmt.Printf("  Suspicious Packages: %d\n", suspicious)
			}
		}
	}

	// Package Details
	fmt.Printf("\nPackage Details:\n")
	fmt.Println(strings.Repeat("-", 80))
	for i, pkg := range result.Packages {
		if pkg == nil {
			continue
		}
		fmt.Printf("\n%d. %s@%s (%s)\n", i+1, pkg.Name, pkg.Version, pkg.Registry)
		
		if showMetadata && pkg.Metadata != nil {
			fmt.Printf("   Description: %s\n", pkg.Metadata.Description)
			fmt.Printf("   Author: %s\n", pkg.Metadata.Author)
			fmt.Printf("   License: %s\n", pkg.Metadata.License)
		}

		// Show threats
		if len(pkg.Threats) > 0 {
			fmt.Printf("   Threats (%d):\n", len(pkg.Threats))
			for _, threat := range pkg.Threats {
				fmt.Printf("     - %s (%s): %s\n", threat.Type, threat.Severity, threat.Description)
				if showEvidence && len(threat.Evidence) > 0 {
					fmt.Printf("       Evidence: %s\n", threat.Evidence[0].Description)
				}
			}
		}

		// Show ML analysis if available
		if mlResults != nil {
			if packages, ok := mlResults["analyzed_packages"].([]map[string]interface{}); ok {
				for _, mlPkg := range packages {
					if name, ok := mlPkg["name"].(string); ok && name == pkg.Name {
						if malicious, ok := mlPkg["malicious_analysis"]; ok {
							fmt.Printf("   ML Analysis: %+v\n", malicious)
						}
						break
					}
				}
			}
		}
	}

	// Recommendations
	fmt.Printf("\nRecommendations:\n")
	fmt.Println(strings.Repeat("-", 80))
	generateRecommendations(result, mlResults)
}

// generateSecurityReport generates a security-focused report
func generateSecurityReport(result *types.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    TYPOSENTINEL SECURITY REPORT")
	fmt.Println(strings.Repeat("=", 80))

	// Security Summary
	fmt.Printf("\nSecurity Summary:\n")
	if result.Summary != nil {
		fmt.Printf("  Total Threats: %d\n", result.Summary.ThreatsFound)
		fmt.Printf("  Critical: %d\n", result.Summary.CriticalThreats)
		fmt.Printf("  High: %d\n", result.Summary.HighThreats)
		fmt.Printf("  Medium: %d\n", result.Summary.MediumThreats)
		fmt.Printf("  Low: %d\n", result.Summary.LowThreats)
	}

	// Threat Details
	fmt.Printf("\nThreat Details:\n")
	fmt.Println(strings.Repeat("-", 80))

	threatCount := 0
	for _, pkg := range result.Packages {
		if pkg == nil || len(pkg.Threats) == 0 {
			continue
		}

		for _, threat := range pkg.Threats {
			threatCount++
			fmt.Printf("\n%d. Package: %s@%s\n", threatCount, pkg.Name, pkg.Version)
			fmt.Printf("   Threat: %s\n", threat.Type)
			fmt.Printf("   Severity: %s\n", threat.Severity)
			fmt.Printf("   Confidence: %.2f\n", threat.Confidence)
			fmt.Printf("   Description: %s\n", threat.Description)
			if threat.Recommendation != "" {
				fmt.Printf("   Recommendation: %s\n", threat.Recommendation)
			}
			if showEvidence && len(threat.Evidence) > 0 {
				fmt.Printf("   Evidence:\n")
				for _, evidence := range threat.Evidence {
					fmt.Printf("     - %s: %s\n", evidence.Type, evidence.Description)
				}
			}
		}
	}

	if threatCount == 0 {
		fmt.Println("No security threats detected.")
	}
}

// generateDependencyReport generates a dependency-focused report
func generateDependencyReport(result *types.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    TYPOSENTINEL DEPENDENCY REPORT")
	fmt.Println(strings.Repeat("=", 80))

	// Dependency Summary
	fmt.Printf("\nDependency Summary:\n")
	if result.Summary != nil {
		fmt.Printf("  Total Packages: %d\n", result.Summary.TotalPackages)
		fmt.Printf("  Clean Packages: %d\n", result.Summary.CleanPackages)
	}

	// Group packages by registry
	registryGroups := make(map[string][]*types.Package)
	for _, pkg := range result.Packages {
		if pkg == nil {
			continue
		}
		registryGroups[pkg.Registry] = append(registryGroups[pkg.Registry], pkg)
	}

	fmt.Printf("\nPackages by Registry:\n")
	fmt.Println(strings.Repeat("-", 80))
	for registry, packages := range registryGroups {
		fmt.Printf("\n%s (%d packages):\n", registry, len(packages))
		
		// Sort packages by name
		sort.Slice(packages, func(i, j int) bool {
			return packages[i].Name < packages[j].Name
		})

		for _, pkg := range packages {
			status := "✓ Clean"
			if len(pkg.Threats) > 0 {
				status = fmt.Sprintf("⚠ %d threats", len(pkg.Threats))
			}
			fmt.Printf("  - %s@%s %s\n", pkg.Name, pkg.Version, status)
			
			if showMetadata && pkg.Metadata != nil {
				fmt.Printf("    Description: %s\n", pkg.Metadata.Description)
				fmt.Printf("    License: %s\n", pkg.Metadata.License)
			}
		}
	}
}

// generateMLReport generates an ML-focused report
func generateMLReport(result *types.ScanResult, mlResults map[string]interface{}) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    TYPOSENTINEL ML ANALYSIS REPORT")
	fmt.Println(strings.Repeat("=", 80))

	if mlResults == nil {
		fmt.Println("\nML analysis not available. Enable ML analysis with --ml-enabled flag.")
		return
	}

	// ML Summary
	fmt.Printf("\nML Analysis Summary:\n")
	if summary, ok := mlResults["summary"].(map[string]interface{}); ok {
		if total, ok := summary["total_packages"].(int); ok {
			fmt.Printf("  Total Packages Analyzed: %d\n", total)
		}
		if malicious, ok := summary["malicious_packages"].(int); ok {
			fmt.Printf("  Malicious Packages: %d\n", malicious)
		}
		if suspicious, ok := summary["suspicious_packages"].(int); ok {
			fmt.Printf("  Suspicious Packages: %d\n", suspicious)
		}
		if timestamp, ok := summary["analysis_timestamp"]; ok {
			fmt.Printf("  Analysis Time: %v\n", timestamp)
		}
	}

	// Detailed ML Results
	fmt.Printf("\nDetailed ML Analysis:\n")
	fmt.Println(strings.Repeat("-", 80))

	if packages, ok := mlResults["analyzed_packages"].([]map[string]interface{}); ok {
		for i, pkg := range packages {
			name, _ := pkg["name"].(string)
			version, _ := pkg["version"].(string)
			registry, _ := pkg["registry"].(string)

			fmt.Printf("\n%d. %s@%s (%s)\n", i+1, name, version, registry)

			// Malicious analysis
			if malicious, ok := pkg["malicious_analysis"]; ok {
				fmt.Printf("   Malicious Analysis: %+v\n", malicious)
			}

			// Similarity analysis
			if similarity, ok := pkg["similarity_analysis"]; ok {
				fmt.Printf("   Similarity Analysis: %+v\n", similarity)
			}

			// Errors
			if err, ok := pkg["malicious_analysis_error"].(string); ok {
				fmt.Printf("   Malicious Analysis Error: %s\n", err)
			}
			if err, ok := pkg["similarity_analysis_error"].(string); ok {
				fmt.Printf("   Similarity Analysis Error: %s\n", err)
			}
		}
	}
}

// printPackageAnalysis prints detailed package analysis
func printPackageAnalysis(analysis *PackageAnalysis) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("                    PACKAGE ANALYSIS: %s\n", analysis.Package.Name)
	fmt.Println(strings.Repeat("=", 80))

	// Basic Information
	fmt.Printf("\nBasic Information:\n")
	fmt.Printf("  Name: %s\n", analysis.Package.Name)
	fmt.Printf("  Version: %s\n", analysis.Package.Version)
	fmt.Printf("  Registry: %s\n", analysis.Package.Registry)
	fmt.Printf("  Analyzed: %s\n", analysis.AnalyzedAt.Format(time.RFC3339))

	// ML Analysis
	if analysis.MLAnalysis != nil {
		fmt.Printf("\nML Analysis:\n")
		fmt.Printf("  Malicious Score: %.3f\n", analysis.MLAnalysis.MaliciousScore)
		fmt.Printf("  Confidence: %.3f\n", analysis.MLAnalysis.MaliciousConfidence)
		fmt.Printf("  Is Malicious: %t\n", analysis.MLAnalysis.IsMalicious)
		fmt.Printf("  Model: %s\n", analysis.MLAnalysis.ModelInfo)

		if len(analysis.MLAnalysis.Reasons) > 0 {
			fmt.Printf("  Reasons:\n")
			for _, reason := range analysis.MLAnalysis.Reasons {
				fmt.Printf("    - %s\n", reason)
			}
		}
	}

	// Similar Packages
	if len(analysis.SimilarPackages) > 0 {
		fmt.Printf("\nSimilar Packages:\n")
		for i, similar := range analysis.SimilarPackages {
			fmt.Printf("  %d. %s (%s) - Similarity: %.3f\n", 
				i+1, similar.Name, similar.Registry, similar.Similarity)
		}
	}

	// Threats
	if len(analysis.Threats) > 0 {
		fmt.Printf("\nThreats Found:\n")
		for i, threat := range analysis.Threats {
			fmt.Printf("  %d. %s (%s)\n", i+1, threat.Type, threat.Severity)
			fmt.Printf("     Description: %s\n", threat.Description)
			fmt.Printf("     Confidence: %.3f\n", threat.Confidence)
		}
	} else {
		fmt.Printf("\nNo threats detected.\n")
	}
}

// printMLResults prints ML analysis results
func printMLResults(mlResults map[string]interface{}) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    ML ANALYSIS RESULTS")
	fmt.Println(strings.Repeat("=", 80))

	if mlResults == nil {
		fmt.Println("\nNo ML results available.")
		return
	}

	// Summary
	if summary, ok := mlResults["summary"].(map[string]interface{}); ok {
		fmt.Printf("\nSummary:\n")
		for key, value := range summary {
			fmt.Printf("  %s: %v\n", strings.Title(strings.ReplaceAll(key, "_", " ")), value)
		}
	}

	// Detailed Results
	if packages, ok := mlResults["analyzed_packages"].([]map[string]interface{}); ok {
		fmt.Printf("\nDetailed Results:\n")
		fmt.Println(strings.Repeat("-", 80))

		for i, pkg := range packages {
			name, _ := pkg["name"].(string)
			version, _ := pkg["version"].(string)
			registry, _ := pkg["registry"].(string)

			fmt.Printf("\n%d. %s@%s (%s)\n", i+1, name, version, registry)

			for key, value := range pkg {
				if key != "name" && key != "version" && key != "registry" {
					fmt.Printf("   %s: %v\n", strings.Title(strings.ReplaceAll(key, "_", " ")), value)
				}
			}
		}
	}
}

// generateRecommendations generates security recommendations
func generateRecommendations(result *types.ScanResult, mlResults map[string]interface{}) {
	recommendations := []string{}

	// Basic recommendations based on threats
	if result.Summary != nil {
		if result.Summary.CriticalThreats > 0 {
			recommendations = append(recommendations, 
				fmt.Sprintf("Immediately address %d critical threats", result.Summary.CriticalThreats))
		}
		if result.Summary.HighThreats > 0 {
			recommendations = append(recommendations, 
				fmt.Sprintf("Review and address %d high-severity threats", result.Summary.HighThreats))
		}
		if result.Summary.ThreatsFound == 0 {
			recommendations = append(recommendations, "No immediate security threats detected")
		}
	}

	// ML-based recommendations
	if mlResults != nil {
		if summary, ok := mlResults["summary"].(map[string]interface{}); ok {
			if malicious, ok := summary["malicious_packages"].(int); ok && malicious > 0 {
				recommendations = append(recommendations, 
					fmt.Sprintf("Remove or replace %d packages flagged as malicious by ML analysis", malicious))
			}
			if suspicious, ok := summary["suspicious_packages"].(int); ok && suspicious > 0 {
				recommendations = append(recommendations, 
					fmt.Sprintf("Investigate %d packages flagged as suspicious by ML analysis", suspicious))
			}
		}
	}

	// General recommendations
	recommendations = append(recommendations, 
		"Regularly update dependencies to latest secure versions",
		"Enable automated security scanning in CI/CD pipeline",
		"Review package licenses for compliance",
		"Monitor package repositories for security advisories")

	for i, rec := range recommendations {
		fmt.Printf("  %d. %s\n", i+1, rec)
	}
}