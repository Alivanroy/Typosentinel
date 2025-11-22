package behavior

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BehaviorService provides high-level behavior analysis functionality
type BehaviorService struct {
	sandbox  *DockerSandboxAgent
	analyzer *BehaviorAnalyzer
}

// NewBehaviorService creates a new behavior analysis service
func NewBehaviorService() (*BehaviorService, error) {
	sandbox, err := NewDockerSandboxAgentWithDefaults()
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox agent: %w", err)
	}

	return &BehaviorService{
		sandbox:  sandbox,
		analyzer: NewBehaviorAnalyzer(),
	}, nil
}

// AnalyzePackage performs complete behavior analysis of a package
func (bs *BehaviorService) AnalyzePackage(ctx context.Context, packageDescriptor types.Dependency) (*BehaviorAnalysis, error) {
	log.Printf("Starting behavior analysis for package: %s@%s", packageDescriptor.Name, packageDescriptor.Version)

	// Convert to package descriptor for sandbox
	sandboxDescriptor := &PackageDescriptor{
		Name:       packageDescriptor.Name,
		Version:    packageDescriptor.Version,
		Ecosystem:  packageDescriptor.Registry,
	}

	// Run sandbox analysis
	profile, err := bs.sandbox.RunSandboxAnalysis(ctx, sandboxDescriptor)
	if err != nil {
		return nil, fmt.Errorf("sandbox analysis failed: %w", err)
	}

	// Analyze the behavior profile
	analysis := bs.analyzer.AnalyzeBehavior(profile)

	log.Printf("Behavior analysis completed for %s: risk_score=%.2f, risk_level=%s, threats=%d",
		packageDescriptor.Name, analysis.RiskScore, analysis.RiskLevel, len(analysis.ThreatsDetected))

	return analysis, nil
}

// AnalyzePackageWithTimeout performs behavior analysis with timeout
func (bs *BehaviorService) AnalyzePackageWithTimeout(ctx context.Context, packageDescriptor types.Dependency, timeout time.Duration) (*BehaviorAnalysis, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return bs.AnalyzePackage(ctx, packageDescriptor)
}

// QuickAnalysis performs a quick behavior analysis (shorter timeout, basic checks)
func (bs *BehaviorService) QuickAnalysis(ctx context.Context, packageDescriptor types.Dependency) (*BehaviorAnalysis, error) {
	// Use shorter timeout for quick analysis
	return bs.AnalyzePackageWithTimeout(ctx, packageDescriptor, 2*time.Minute)
}

// DeepAnalysis performs a comprehensive behavior analysis (longer timeout, thorough checks)
func (bs *BehaviorService) DeepAnalysis(ctx context.Context, packageDescriptor types.Dependency) (*BehaviorAnalysis, error) {
	// Use longer timeout for deep analysis
	return bs.AnalyzePackageWithTimeout(ctx, packageDescriptor, 10*time.Minute)
}

// BatchAnalyze analyzes multiple packages in parallel
func (bs *BehaviorService) BatchAnalyze(ctx context.Context, packageDescriptors []types.Dependency) ([]*BehaviorAnalysis, error) {
	results := make([]*BehaviorAnalysis, len(packageDescriptors))
	errors := make([]error, len(packageDescriptors))

	// Create a channel to limit concurrent analyses
	semaphore := make(chan struct{}, 3) // Max 3 concurrent analyses

	for i, descriptor := range packageDescriptors {
		semaphore <- struct{}{} // Acquire semaphore
		
		go func(index int, pkg types.Dependency) {
			defer func() { <-semaphore }() // Release semaphore
			
			analysis, err := bs.AnalyzePackage(ctx, pkg)
			if err != nil {
				errors[index] = err
				log.Printf("Behavior analysis failed for %s: %v", pkg.Name, err)
				return
			}
			
			results[index] = analysis
		}(i, descriptor)
	}

	// Wait for all analyses to complete
	for i := 0; i < len(packageDescriptors); i++ {
		<-semaphore
	}

	// Check for errors
	var finalError error
	for _, err := range errors {
		if err != nil {
			if finalError == nil {
				finalError = err
			}
		}
	}

	if finalError != nil {
		return results, fmt.Errorf("some analyses failed: %w", finalError)
	}

	return results, nil
}

// ConvertToScanResult converts behavior analysis to dependency scan result
func (bs *BehaviorService) ConvertToScanResult(analysis *BehaviorAnalysis, packageDescriptor types.Dependency) *types.ScanResult {
	// Convert threats to the proper format
	threats := make([]types.Threat, len(analysis.ThreatsDetected))
	for i, threat := range analysis.ThreatsDetected {
		severity := types.SeverityLow
		severityFloat, _ := strconv.ParseFloat(threat.Severity, 64)
		switch {
		case severityFloat >= 8.0:
			severity = types.SeverityCritical
		case severityFloat >= 6.0:
			severity = types.SeverityHigh
		case severityFloat >= 4.0:
			severity = types.SeverityMedium
		}
		
		threats[i] = types.Threat{
			ID:          fmt.Sprintf("behavior_%s_%d", analysis.PackageID, i),
			Package:     packageDescriptor.Name,
			Version:     packageDescriptor.Version,
			Registry:    packageDescriptor.Registry,
			Type:        types.ThreatTypeMaliciousPackage,
			Severity:    severity,
			Confidence:  0.9, // High confidence for behavior analysis
			Description: threat.Description,
			Evidence: []types.Evidence{
				{
					Type:        "behavioral",
					Description: threat.Type,
					Value:       threat.Evidence,
					Score:       severityFloat,
				},
			},
			DetectedAt:      analysis.AnalysisTime,
			DetectionMethod: "behavioral_analysis",
		}
	}

	return &types.ScanResult{
		ID:        fmt.Sprintf("behavior_%s", analysis.PackageID),
		PackageID: analysis.PackageID,
		Target:    packageDescriptor.Name,
		Type:      "behavioral_analysis",
		ScanType:  "behavioral",
		Status:    "completed",
		OverallRisk: analysis.RiskLevel,
		RiskScore: analysis.RiskScore,
		Packages: []*types.Package{
			{
				Name:      packageDescriptor.Name,
				Version:   packageDescriptor.Version,
				Registry:  packageDescriptor.Registry,
				Threats:   threats,
				RiskLevel: types.SeverityHigh, // Will be recalculated based on threats
				RiskScore: analysis.RiskScore,
				AnalyzedAt: analysis.AnalysisTime,
			},
		},
		CreatedAt: analysis.AnalysisTime,
		Metadata: map[string]interface{}{
			"behavior_analysis": analysis,
			"ecosystem":         packageDescriptor.Registry,
		},
	}
}

// GetBehaviorSummary returns a human-readable summary of the behavior analysis
func (bs *BehaviorService) GetBehaviorSummary(analysis *BehaviorAnalysis) string {
	summary := fmt.Sprintf("Behavior Analysis Summary for %s\n", analysis.PackageID)
	summary += fmt.Sprintf("Risk Score: %.2f/100 (%s risk)\n", analysis.RiskScore, analysis.RiskLevel)
	summary += fmt.Sprintf("Threats Detected: %d\n", len(analysis.ThreatsDetected))
	
	if len(analysis.ThreatsDetected) > 0 {
		summary += "Critical Threats:\n"
		for _, threat := range analysis.ThreatsDetected {
			severityFloat, _ := strconv.ParseFloat(threat.Severity, 64)
			if severityFloat >= 7.0 {
				summary += fmt.Sprintf("  - [%s] %s (severity: %.1f)\n", threat.Type, threat.Description, severityFloat)
			}
		}
	}
	
	summary += fmt.Sprintf("\nTotal Actions: %d\n", analysis.BehaviorSummary.TotalActions)
	summary += fmt.Sprintf("Critical Actions: %d\n", analysis.BehaviorSummary.CriticalActions)
	
	if len(analysis.BehaviorSummary.RiskFactors) > 0 {
		summary += "Risk Factors:\n"
		for _, factor := range analysis.BehaviorSummary.RiskFactors {
			summary += fmt.Sprintf("  - %s\n", factor)
		}
	}
	
	if len(analysis.BehaviorSummary.Recommendations) > 0 {
		summary += "Recommendations:\n"
		for _, rec := range analysis.BehaviorSummary.Recommendations {
			summary += fmt.Sprintf("  - %s\n", rec)
		}
	}
	
	return summary
}

// convertThreats converts behavior threats to model threats
func (bs *BehaviorService) convertThreats(threats []BehaviorThreat) []types.Threat {
	return bs.analyzer.convertThreats(threats)
}

// HealthCheck performs a health check of the behavior service
func (bs *BehaviorService) HealthCheck(ctx context.Context) error {
	// Check if Docker is available
	if err := bs.sandbox.HealthCheck(ctx); err != nil {
		return fmt.Errorf("sandbox health check failed: %w", err)
	}
	
	return nil
}

// Close cleans up resources
func (bs *BehaviorService) Close() error {
	if bs.sandbox != nil {
		return bs.sandbox.Close()
	}
	return nil
}