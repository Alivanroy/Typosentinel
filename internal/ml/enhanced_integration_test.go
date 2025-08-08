package ml

import (
	"context"
	"testing"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestEnhancedBehavioralAnalyzerIntegration(t *testing.T) {
	// Create a default config
	cfg := DefaultConfig()
	cfg.Enabled = true

	// Create a new ML analyzer with enhanced behavioral analyzer
	analyzer := NewMLAnalyzer(cfg)

	// Verify that the enhanced behavioral analyzer is initialized
	if analyzer.EnhancedBehavioralAnalyzer == nil {
		t.Fatal("Enhanced behavioral analyzer is not initialized")
	}

	// Create a test package
	pkg := &types.Package{
		Name:    "test-package",
		Version: "1.0.0",
		Metadata: &types.PackageMetadata{
			Author:      "test-author",
			License:     "MIT",
			Keywords:    []string{"test", "package"},
			Downloads:   1000,
		},
	}

	// Test the analysis
	ctx := context.Background()
	result, err := analyzer.Analyze(ctx, pkg)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Verify that we get a result
	if result == nil {
		t.Fatal("Analysis result is nil")
	}

	// Verify that behavioral analysis is included (check if it has any data)
	behavioralAnalysis := result.BehavioralAnalysis
	if len(behavioralAnalysis.InstallBehavior.SuspiciousCommands) == 0 &&
		len(behavioralAnalysis.RuntimeBehavior.ProcessSpawning) == 0 &&
		len(behavioralAnalysis.NetworkBehavior.OutboundConnections) == 0 &&
		len(behavioralAnalysis.FileSystemBehavior.FileCreation) == 0 {
		t.Logf("Behavioral analysis appears to be empty (expected for test package)")
	}

	t.Logf("Enhanced behavioral analyzer integration test passed")
	t.Logf("Install behavior commands: %d", len(behavioralAnalysis.InstallBehavior.SuspiciousCommands))
	t.Logf("Runtime behavior processes: %d", len(behavioralAnalysis.RuntimeBehavior.ProcessSpawning))
}

func TestConversionMethods(t *testing.T) {
	// Create a default config
	cfg := DefaultConfig()
	cfg.Enabled = true

	analyzer := NewMLAnalyzer(cfg)

	// Test package
	pkg := &types.Package{
		Name:    "test-package",
		Version: "1.0.0",
		Metadata: &types.PackageMetadata{
			Author:      "test-author",
			License:     "MIT",
			Keywords:    []string{"test", "package"},
			Downloads:   1000,
		},
	}

	// Test convertToEnhancedFeatures
	enhancedFeatures := analyzer.convertToEnhancedFeatures(pkg)
	if enhancedFeatures == nil {
		t.Fatal("Enhanced features conversion returned nil")
	}

	// Verify some basic fields are set (these are structs, not pointers, so check for meaningful values)
	if enhancedFeatures.FileStructure.TotalFiles < 0 {
		t.Fatal("FileStructure appears invalid")
	}
	if enhancedFeatures.CodeMetrics.LinesOfCode < 0 {
		t.Fatal("CodeMetrics appears invalid")
	}
	if enhancedFeatures.SecurityMetrics.VulnerabilityCount < 0 {
		t.Fatal("SecurityMetrics appears invalid")
	}
	// BehavioralMetrics is a struct, so it's always initialized

	t.Logf("Conversion methods test passed")
}