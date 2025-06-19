package cmd

import (
	"fmt"
	"os"
	"time"

	"typosentinel/internal/config"
	"typosentinel/internal/output"
	"typosentinel/internal/scanner"
)

// convertToOutputFormat converts scanner results to the new output format
func convertToOutputFormat(results *scanner.ScanResults, cfg *config.Config) *output.ScanResult {
	if results == nil {
		return &output.ScanResult{
			Findings: []output.Finding{},
			Summary:  output.ScanSummary{},
			Metadata: output.ScanMetadata{},
		}
	}

	// Convert findings
	var findings []output.Finding
	for _, result := range results.Results {
		for _, threat := range result.Threats {
			finding := output.Finding{
				PackageName:    result.Package.Name,
				PackageVersion: result.Package.Version,
				ThreatType:     threat.Type,
				Severity:       mapSeverity(threat.Severity),
				RiskScore:      threat.Score,
				Description:    threat.Description,
				Recommendation: threat.Recommendation,
				Evidence:       threat.Evidence,
				Source:         threat.Source,
				Confidence:     threat.Confidence,
			}

			// Add additional context
			if result.Package.Registry != "" {
				finding.Registry = result.Package.Registry
			}

			if result.Package.URL != "" {
				finding.PackageURL = result.Package.URL
			}

			findings = append(findings, finding)
		}
	}

	// Calculate summary statistics
	summary := calculateSummary(findings, results)

	// Create metadata
	metadata := output.ScanMetadata{
		ScanID:        generateScanID(),
		Timestamp:     time.Now(),
		Duration:      results.Duration,
		ScannedPath:   results.ScanPath,
		ConfigFile:    cfg.GetConfigFile(),
		Version:       "1.0.0", // TODO: Get from build info
		TotalPackages: results.TotalPackages,
		Analyzers:     getEnabledAnalyzers(cfg),
	}

	return &output.ScanResult{
		Findings: findings,
		Summary:  summary,
		Metadata: metadata,
	}
}

// calculateSummary calculates summary statistics from findings
func calculateSummary(findings []output.Finding, results *scanner.ScanResults) output.ScanSummary {
	summary := output.ScanSummary{
		TotalFindings: len(findings),
	}

	// Count by severity
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		case "info":
			summary.InfoCount++
		}
	}

	// Calculate overall risk
	if summary.CriticalCount > 0 {
		summary.OverallRisk = "critical"
	} else if summary.HighCount > 0 {
		summary.OverallRisk = "high"
	} else if summary.MediumCount > 0 {
		summary.OverallRisk = "medium"
	} else if summary.LowCount > 0 {
		summary.OverallRisk = "low"
	} else {
		summary.OverallRisk = "minimal"
	}

	// Calculate risk score (weighted average)
	totalScore := 0.0
	totalWeight := 0.0
	for _, finding := range findings {
		weight := getSeverityWeight(finding.Severity)
		totalScore += finding.RiskScore * weight
		totalWeight += weight
	}

	if totalWeight > 0 {
		summary.AverageRiskScore = totalScore / totalWeight
	}

	// Set recommendations
	summary.Recommendations = generateRecommendations(summary, findings)

	return summary
}

// mapSeverity maps internal severity levels to output format
func mapSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM", "MODERATE":
		return "medium"
	case "LOW":
		return "low"
	case "INFO", "MINIMAL":
		return "info"
	default:
		return "unknown"
	}
}

// getSeverityWeight returns weight for severity level
func getSeverityWeight(severity string) float64 {
	switch severity {
	case "critical":
		return 5.0
	case "high":
		return 4.0
	case "medium":
		return 3.0
	case "low":
		return 2.0
	case "info":
		return 1.0
	default:
		return 1.0
	}
}

// generateRecommendations generates recommendations based on findings
func generateRecommendations(summary output.ScanSummary, findings []output.Finding) []string {
	var recommendations []string

	if summary.CriticalCount > 0 {
		recommendations = append(recommendations, "Immediate action required: Critical vulnerabilities found")
		recommendations = append(recommendations, "Review and replace all packages with critical risk scores")
	}

	if summary.HighCount > 0 {
		recommendations = append(recommendations, "High-priority review needed for flagged packages")
		recommendations = append(recommendations, "Consider alternative packages or verify legitimacy")
	}

	if summary.MediumCount > 0 {
		recommendations = append(recommendations, "Monitor flagged packages for suspicious activity")
	}

	if summary.TotalFindings == 0 {
		recommendations = append(recommendations, "No security issues detected in scanned packages")
		recommendations = append(recommendations, "Continue regular security monitoring")
	}

	// Add specific recommendations based on threat types
	threatTypes := make(map[string]bool)
	for _, finding := range findings {
		threatTypes[finding.ThreatType] = true
	}

	if threatTypes["typosquatting"] {
		recommendations = append(recommendations, "Enable typosquatting protection in your package manager")
	}

	if threatTypes["dependency_confusion"] {
		recommendations = append(recommendations, "Review internal package naming conventions")
	}

	return recommendations
}

// getEnabledAnalyzers returns list of enabled analyzers
func getEnabledAnalyzers(cfg *config.Config) []string {
	var analyzers []string

	if cfg.Scanner.EnableStaticAnalysis {
		analyzers = append(analyzers, "static")
	}

	if cfg.Scanner.EnableDynamicAnalysis {
		analyzers = append(analyzers, "dynamic")
	}

	if cfg.Scanner.EnableMLAnalysis {
		analyzers = append(analyzers, "ml")
	}

	if cfg.Scanner.EnableProvenanceAnalysis {
		analyzers = append(analyzers, "provenance")
	}

	return analyzers
}

// generateScanID generates a unique scan identifier
func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().Unix())
}

// handleExitCode determines exit code based on scan results
func handleExitCode(result *output.ScanResult, cfg *config.Config) error {
	if result == nil {
		return nil
	}

	// Check if we should fail on threats
	if cfg.Policies.FailOnThreats {
		switch result.Summary.OverallRisk {
		case "critical":
			os.Exit(3) // Critical threats found
		case "high":
			os.Exit(2) // High threats found
		case "medium":
			if cfg.Policies.MinThreatLevel == "medium" || cfg.Policies.MinThreatLevel == "low" {
				os.Exit(1) // Medium threats found
			}
		case "low":
			if cfg.Policies.MinThreatLevel == "low" {
				os.Exit(1) // Low threats found
			}
		}
	}

	return nil
}

// validateOutputFormat validates the output format
func validateOutputFormat(format string) error {
	validFormats := []string{"json", "yaml", "text", "table", "compact", "detailed", "summary"}
	for _, valid := range validFormats {
		if format == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid output format '%s', must be one of: %v", format, validFormats)
}

// ensureOutputDirectory ensures the output directory exists
func ensureOutputDirectory(outputFile string) error {
	if outputFile == "" {
		return nil
	}

	dir := filepath.Dir(outputFile)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	return nil
}

// getOutputWriter returns the appropriate output writer
func getOutputWriter(outputFile string) (*os.File, error) {
	if outputFile == "" {
		return os.Stdout, nil
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	return file, nil
}