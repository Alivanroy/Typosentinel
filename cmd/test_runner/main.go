package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/typosentinel/typosentinel/internal/testing"
)

func main() {
	// Command line flags
	configPath := flag.String("config", "./configs/enhanced.yaml", "Path to configuration file")
	outputDir := flag.String("output", "./test_results", "Output directory for test results")
	timeout := flag.Duration("timeout", 30*time.Minute, "Overall test timeout")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	exportFormat := flag.String("format", "json", "Export format (json)")
	fineTune := flag.Bool("fine-tune", false, "Enable ML model fine-tuning")
	flag.Parse()

	// Setup logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}

	fmt.Println("🔍 Typosentinel Comprehensive Detection Test Suite")
	fmt.Println("=================================================")
	fmt.Printf("Configuration: %s\n", *configPath)
	fmt.Printf("Output Directory: %s\n", *outputDir)
	fmt.Printf("Timeout: %v\n", *timeout)
	fmt.Println()

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Initialize test suite
	fmt.Println("🚀 Initializing test suite...")
	testSuite, err := testing.NewComprehensiveTestSuite(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize test suite: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Run comprehensive tests
	fmt.Println("🧪 Running comprehensive detection tests...")
	startTime := time.Now()

	results, err := testSuite.RunComprehensiveTests(ctx)
	if err != nil {
		log.Fatalf("Failed to run tests: %v", err)
	}

	totalTime := time.Since(startTime)
	fmt.Printf("\n✅ Tests completed in %v\n\n", totalTime)

	// Run fine-tuning if requested
	if *fineTune {
		fmt.Println("🔧 Starting ML model fine-tuning...")
		if err := testSuite.RunFineTuning(ctx, *verbose); err != nil {
			log.Printf("Warning: Fine-tuning failed: %v", err)
		} else {
			fmt.Println("✅ Fine-tuning completed successfully")
		}
		fmt.Println()
	}

	// Display results summary
	displayResultsSummary(results)

	// Export detailed results
	fmt.Printf("📊 Exporting detailed results to %s...\n", *outputDir)
	if err := testSuite.ExportResults(*exportFormat, *outputDir); err != nil {
		log.Printf("Warning: Failed to export results: %v", err)
	}

	// Generate effectiveness report
	generateEffectivenessReport(results, *outputDir)

	// Exit with appropriate code
	if results.Summary.EffectivenessScore >= 0.99 {
		fmt.Println("\n🎉 SUCCESS: Detection effectiveness target achieved (≥99%)!")
		os.Exit(0)
	} else {
		fmt.Printf("\n⚠️  WARNING: Detection effectiveness below target (%.1f%% < 99%%)\n", results.Summary.EffectivenessScore*100)
		fmt.Println("Review the detailed report for improvement recommendations.")
		os.Exit(1)
	}
}

func displayResultsSummary(results *testing.TestResults) {
	fmt.Println("📈 TEST RESULTS SUMMARY")
	fmt.Println("======================")
	fmt.Printf("Overall Grade: %s\n", results.Summary.OverallGrade)
	fmt.Printf("Effectiveness Score: %.1f%%\n", results.Summary.EffectivenessScore*100)
	fmt.Printf("Total Tests: %d\n", results.TotalTests)
	fmt.Printf("Passed: %d\n", results.PassedTests)
	fmt.Printf("Failed: %d\n", results.FailedTests)
	fmt.Printf("Overall Accuracy: %.1f%%\n", results.OverallAccuracy*100)
	fmt.Printf("Detection Rate: %.1f%%\n", results.DetectionRate*100)
	fmt.Printf("False Positive Rate: %.1f%%\n", results.FalsePositiveRate*100)
	fmt.Printf("False Negative Rate: %.1f%%\n", results.FalseNegativeRate*100)
	fmt.Printf("Average Response Time: %v\n", results.AverageResponseTime)
	fmt.Println()

	// Detector performance breakdown
	fmt.Println("🔧 DETECTOR PERFORMANCE")
	fmt.Println("=======================")
	for detectorName, metrics := range results.DetectorResults {
		fmt.Printf("%s Detector:\n", detectorName)
		fmt.Printf("  Accuracy: %.1f%%\n", metrics.Accuracy*100)
		fmt.Printf("  Precision: %.1f%%\n", metrics.Precision*100)
		fmt.Printf("  Recall: %.1f%%\n", metrics.Recall*100)
		fmt.Printf("  F1 Score: %.1f%%\n", metrics.F1Score*100)
		fmt.Printf("  Response Time: %v\n", metrics.AverageResponseTime)
		fmt.Printf("  False Positives: %d\n", metrics.FalsePositives)
		fmt.Printf("  False Negatives: %d\n", metrics.FalseNegatives)
		fmt.Println()
	}

	// Key findings
	if len(results.Summary.KeyFindings) > 0 {
		fmt.Println("🔍 KEY FINDINGS")
		fmt.Println("===============")
		for _, finding := range results.Summary.KeyFindings {
			fmt.Printf("• %s\n", finding)
		}
		fmt.Println()
	}

	// Critical issues
	if len(results.Summary.CriticalIssues) > 0 {
		fmt.Println("🚨 CRITICAL ISSUES")
		fmt.Println("==================")
		for _, issue := range results.Summary.CriticalIssues {
			fmt.Printf("• %s\n", issue)
		}
		fmt.Println()
	}

	// Recommendations
	if len(results.Recommendations) > 0 {
		fmt.Println("💡 RECOMMENDATIONS")
		fmt.Println("==================")
		for _, rec := range results.Recommendations {
			fmt.Printf("• %s\n", rec)
		}
		fmt.Println()
	}
}

func generateEffectivenessReport(results *testing.TestResults, outputDir string) {
	reportPath := filepath.Join(outputDir, "effectiveness_report.md")

	report := fmt.Sprintf(`# Typosentinel Detection Effectiveness Report

Generated: %s

## Executive Summary

**Overall Grade:** %s  
**Effectiveness Score:** %.1f%%  
**Compliance Status:** %s

### Key Metrics
- **Total Tests Executed:** %d
- **Tests Passed:** %d (%.1f%%)
- **Tests Failed:** %d (%.1f%%)
- **Overall Accuracy:** %.1f%%
- **Average Response Time:** %v

## Detection Performance by Component

`,
		results.Timestamp.Format("2006-01-02 15:04:05"),
		results.Summary.OverallGrade,
		results.Summary.EffectivenessScore*100,
		results.Summary.ComplianceStatus,
		results.TotalTests,
		results.PassedTests,
		float64(results.PassedTests)/float64(results.TotalTests)*100,
		results.FailedTests,
		float64(results.FailedTests)/float64(results.TotalTests)*100,
		results.OverallAccuracy*100,
		results.AverageResponseTime,
	)

	// Add detector performance table
	report += "| Detector | Accuracy | Precision | Recall | F1 Score | Avg Response Time | False Positives | False Negatives |\n"
	report += "|----------|----------|-----------|--------|----------|-------------------|-----------------|-----------------|\n"

	for detectorName, metrics := range results.DetectorResults {
		report += fmt.Sprintf("| %s | %.1f%% | %.1f%% | %.1f%% | %.1f%% | %v | %d | %d |\n",
			detectorName,
			metrics.Accuracy*100,
			metrics.Precision*100,
			metrics.Recall*100,
			metrics.F1Score*100,
			metrics.AverageResponseTime,
			metrics.FalsePositives,
			metrics.FalseNegatives,
		)
	}

	// Add key findings
	if len(results.Summary.KeyFindings) > 0 {
		report += "\n## Key Findings\n\n"
		for _, finding := range results.Summary.KeyFindings {
			report += fmt.Sprintf("- %s\n", finding)
		}
	}

	// Add critical issues
	if len(results.Summary.CriticalIssues) > 0 {
		report += "\n## Critical Issues\n\n"
		for _, issue := range results.Summary.CriticalIssues {
			report += fmt.Sprintf("- ⚠️ %s\n", issue)
		}
	}

	// Add recommendations
	if len(results.Recommendations) > 0 {
		report += "\n## Recommendations\n\n"
		for _, rec := range results.Recommendations {
			report += fmt.Sprintf("- %s\n", rec)
		}
	}

	// Add next steps
	if len(results.Summary.NextSteps) > 0 {
		report += "\n## Next Steps\n\n"
		for _, step := range results.Summary.NextSteps {
			report += fmt.Sprintf("1. %s\n", step)
		}
	}

	// Add performance metrics
	report += fmt.Sprintf(`
## Performance Metrics

- **Total Execution Time:** %v
- **Average Test Time:** %v
- **Throughput:** %.1f tests/second
- **Memory Usage:** %.1f MB
- **CPU Usage:** %.1f%%

## Test Case Details

`,
		results.PerformanceMetrics.TotalExecutionTime,
		results.PerformanceMetrics.AverageTestTime,
		results.PerformanceMetrics.Throughput,
		results.PerformanceMetrics.MemoryUsage,
		results.PerformanceMetrics.CPUUsage,
	)

	// Add test case results table
	report += "| Test Case | Status | Detected | Threat Type | Confidence | Response Time | IOCs Found |\n"
	report += "|-----------|--------|----------|-------------|------------|---------------|------------|\n"

	for _, testResult := range results.TestCaseResults {
		status := "✅ PASS"
		if !testResult.Passed {
			status = "❌ FAIL"
		}

		detected := "No"
		if testResult.Detected {
			detected = "Yes"
		}

		report += fmt.Sprintf("| %s | %s | %s | %s | %.1f%% | %v | %d |\n",
			testResult.TestCase.Name,
			status,
			detected,
			testResult.ThreatType,
			testResult.Confidence*100,
			testResult.ResponseTime,
			len(testResult.IOCsFound),
		)
	}

	// Add conclusion
	conclusion := "\n## Conclusion\n\n"
	if results.Summary.EffectivenessScore >= 0.99 {
		conclusion += "🎉 **SUCCESS**: The Typosentinel detection system has achieved the target effectiveness of 99% or higher. "
		conclusion += "The system is ready for production deployment with confidence in its ability to detect malicious packages.\n\n"
	} else {
		conclusion += fmt.Sprintf("⚠️ **IMPROVEMENT NEEDED**: The current effectiveness score of %.1f%% is below the 99%% target. ", results.Summary.EffectivenessScore*100)
		conclusion += "Review the recommendations above and implement the suggested improvements before production deployment.\n\n"
	}

	conclusion += "### Compliance Assessment\n\n"
	switch results.Summary.ComplianceStatus {
	case "COMPLIANT":
		conclusion += "✅ **COMPLIANT**: The system meets all detection effectiveness requirements.\n"
	case "PARTIALLY_COMPLIANT":
		conclusion += "⚠️ **PARTIALLY COMPLIANT**: The system meets basic requirements but has room for improvement.\n"
	default:
		conclusion += "❌ **NON-COMPLIANT**: The system does not meet minimum detection effectiveness requirements.\n"
	}

	report += conclusion

	// Write report to file
	if err := os.WriteFile(reportPath, []byte(report), 0644); err != nil {
		log.Printf("Warning: Failed to write effectiveness report: %v", err)
	} else {
		fmt.Printf("📄 Effectiveness report saved to: %s\n", reportPath)
	}
}