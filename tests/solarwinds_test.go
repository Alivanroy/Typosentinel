package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSolarWindsSupplyChainAttackDetection tests SolarWinds-style supply chain attack detection
func TestSolarWindsSupplyChainAttackDetection(t *testing.T) {
	ctx := context.Background()
	
	// Initialize enhanced scanner for supply chain analysis
	enhancedScanner := setupSolarWindsScanner(t)
	
	t.Run("DetectCompromisedBuildProcess", func(t *testing.T) {
		testCompromisedBuildProcessDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectMaliciousCodeInjection", func(t *testing.T) {
		testMaliciousCodeInjectionDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectSuspiciousNetworkActivity", func(t *testing.T) {
		testSuspiciousNetworkActivityDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectBuildIntegrityViolations", func(t *testing.T) {
		testBuildIntegrityViolationDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectSupplyChainCompromise", func(t *testing.T) {
		testSupplyChainCompromiseDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("DetectBackdoorPatterns", func(t *testing.T) {
		testBackdoorPatternDetection(t, ctx, enhancedScanner)
	})
	
	t.Run("ValidateCodeSigningIntegrity", func(t *testing.T) {
		testCodeSigningIntegrityValidation(t, ctx, enhancedScanner)
	})
}

func testCompromisedBuildProcessDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test detection of compromised build processes similar to SolarWinds
	testCases := []struct {
		name           string
		packageName    string
		buildIndicator string
		expectedThreat bool
		description    string
	}{
		{
			name:           "NormalBuildProcess",
			packageName:    "legitimate-package",
			buildIndicator: "standard_build_process",
			expectedThreat: false,
			description:    "Normal build process should not trigger alerts",
		},
		{
			name:           "UnauthorizedBuildModification",
			packageName:    "compromised-package",
			buildIndicator: "unauthorized_build_modification",
			expectedThreat: true,
			description:    "Unauthorized build modifications should be detected",
		},
		{
			name:           "SuspiciousBuildScript",
			packageName:    "suspicious-build-package",
			buildIndicator: "suspicious_build_script_injection",
			expectedThreat: true,
			description:    "Suspicious build script injections should be detected",
		},
		{
			name:           "CompromisedBuildEnvironment",
			packageName:    "env-compromised-package",
			buildIndicator: "compromised_build_environment",
			expectedThreat: true,
			description:    "Compromised build environments should be detected",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := createSolarWindsTestPackage(tc.packageName, "1.0.0", tc.buildIndicator)
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check for build integrity findings
			hasBuildThreat := false
			if len(result.BuildIntegrityFindings) > 0 {
				for _, finding := range result.BuildIntegrityFindings {
					if finding.Type == "compromised_build_process" {
						hasBuildThreat = true
						break
					}
				}
			}
			
			assert.Equal(t, tc.expectedThreat, hasBuildThreat, tc.description)
		})
	}
}

func testMaliciousCodeInjectionDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test detection of malicious code injection patterns
	maliciousPatterns := []struct {
		name        string
		codePattern string
		severity    types.Severity
	}{
		{
			name:        "DomainGenerationAlgorithm",
			codePattern: "generateDomainFromSeed(seed, timestamp)",
			severity:    types.SeverityCritical,
		},
		{
			name:        "EncryptedPayloadExfiltration",
			codePattern: "encryptAndExfiltrate(sensitiveData, remoteEndpoint)",
			severity:    types.SeverityCritical,
		},
		{
			name:        "StealthyNetworkCommunication",
			codePattern: "establishCovertChannel(targetHost, hiddenPort)",
			severity:    types.SeverityHigh,
		},
		{
			name:        "SystemInformationGathering",
			codePattern: "collectSystemFingerprint(includeNetworkInfo)",
			severity:    types.SeverityHigh,
		},
		{
			name:        "PersistenceMechanism",
			codePattern: "installPersistentBackdoor(systemPath, triggerCondition)",
			severity:    types.SeverityCritical,
		},
	}
	
	for _, pattern := range maliciousPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			pkg := createSolarWindsTestPackageWithCode(
				"solarwinds-style-package",
				"1.0.0",
				pattern.codePattern,
			)
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check for malicious code detection
			hasMaliciousCode := false
			for _, pkg := range result.Packages {
				for _, threat := range pkg.Threats {
					if threat.Type == types.ThreatTypeMaliciousPackage && threat.Severity >= pattern.severity {
						hasMaliciousCode = true
						break
					}
				}
			}
			
			assert.True(t, hasMaliciousCode, "Should detect malicious pattern: %s", pattern.codePattern)
		})
	}
}

func testSuspiciousNetworkActivityDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test detection of suspicious network activity patterns
	networkPatterns := []struct {
		name           string
		networkPattern string
		expectedThreat bool
	}{
		{
			name:           "LegitimateAPICall",
			networkPattern: "https://api.legitimate-service.com/v1/data",
			expectedThreat: false,
		},
		{
			name:           "SuspiciousDomainCommunication",
			networkPattern: "https://avsvmcloud.com/api/collect",
			expectedThreat: true,
		},
		{
			name:           "UnusualPortCommunication",
			networkPattern: "tcp://suspicious-host.com:8443",
			expectedThreat: true,
		},
		{
			name:           "EncryptedExfiltrationChannel",
			networkPattern: "wss://hidden-endpoint.net/secure-channel",
			expectedThreat: true,
		},
	}
	
	for _, pattern := range networkPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			pkg := createSolarWindsTestPackageWithNetworkActivity(
				"network-activity-package",
				"1.0.0",
				pattern.networkPattern,
			)
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check for suspicious network activity
			hasSuspiciousNetwork := false
			for _, pkg := range result.Packages {
				for _, threat := range pkg.Threats {
					if threat.Type == types.ThreatTypeSuspicious {
						hasSuspiciousNetwork = true
						break
					}
				}
			}
			
			assert.Equal(t, pattern.expectedThreat, hasSuspiciousNetwork)
		})
	}
}

func testBuildIntegrityViolationDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test detection of build integrity violations
	pkg := createSolarWindsTestPackage("integrity-test-package", "1.0.0", "integrity_violation")
	
	result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
	require.NoError(t, err)
	
	// Check for build integrity findings
	assert.NotNil(t, result.BuildIntegrityFindings)
	
	for _, finding := range result.BuildIntegrityFindings {
		assert.NotEmpty(t, finding.ID)
		assert.NotEmpty(t, finding.Type)
		assert.True(t, finding.Confidence > 0.0)
		assert.NotZero(t, finding.DetectedAt)
		
		// Verify evidence is provided
		assert.NotEmpty(t, finding.Evidence)
		for _, evidence := range finding.Evidence {
			assert.NotEmpty(t, evidence.Type)
			assert.NotEmpty(t, evidence.Description)
		}
	}
}

func testSupplyChainCompromiseDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test detection of supply chain compromise indicators
	pkg := createSolarWindsTestPackageWithDependencies("supply-chain-package", "1.0.0", []string{
		"compromised-dependency@1.0.0",
		"suspicious-lib@2.1.0",
		"backdoored-util@1.5.0",
	})
	
	result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
	require.NoError(t, err)
	
	// Check supply chain risk assessment
	assert.NotNil(t, result.SupplyChainRisk)
	assert.True(t, result.SupplyChainRisk.OverallScore >= 0.0)
	assert.True(t, result.SupplyChainRisk.OverallScore <= 1.0)
	assert.NotEmpty(t, result.SupplyChainRisk.Factors)
	assert.NotEmpty(t, result.SupplyChainRisk.Recommendations)
	
	// Check dependency graph analysis
	assert.NotNil(t, result.DependencyGraph)
	assert.True(t, len(result.DependencyGraph.Nodes) > 0)
	assert.True(t, result.DependencyGraph.Depth > 0)
}

func testBackdoorPatternDetection(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test detection of backdoor patterns similar to SolarWinds
	backdoorPatterns := []string{
		"if (isValidDomain(targetDomain)) { executePayload(); }",
		"setTimeout(() => { collectAndTransmit(); }, randomDelay);",
		"const payload = decryptPayload(encryptedData, derivedKey);",
		"if (environmentCheck() && timeWindowValid()) { activateBackdoor(); }",
	}
	
	for i, pattern := range backdoorPatterns {
		t.Run(fmt.Sprintf("BackdoorPattern_%d", i+1), func(t *testing.T) {
			pkg := createSolarWindsTestPackageWithCode(
				"backdoor-test-package",
				"1.0.0",
				pattern,
			)
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check for zero-day findings (backdoor patterns)
			hasBackdoorPattern := false
			for _, finding := range result.ZeroDayFindings {
				if finding.BehaviorType == "backdoor_pattern" {
					hasBackdoorPattern = true
					assert.True(t, finding.AnomalyScore > 0.7)
					assert.NotEmpty(t, finding.Recommendation)
					break
				}
			}
			
			assert.True(t, hasBackdoorPattern, "Should detect backdoor pattern: %s", pattern)
		})
	}
}

func testCodeSigningIntegrityValidation(t *testing.T, ctx context.Context, scanner *scanner.EnhancedScanner) {
	// Test code signing integrity validation
	testCases := []struct {
		name           string
		packageName    string
		signatureValid bool
		expectedResult bool
	}{
		{
			name:           "ValidSignature",
			packageName:    "signed-package",
			signatureValid: true,
			expectedResult: true,
		},
		{
			name:           "InvalidSignature",
			packageName:    "unsigned-package",
			signatureValid: false,
			expectedResult: false,
		},
		{
			name:           "TamperedSignature",
			packageName:    "tampered-package",
			signatureValid: false,
			expectedResult: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkg := createSolarWindsTestPackageWithSignature(tc.packageName, "1.0.0", tc.signatureValid)
			
			result, err := scanner.ScanWithSupplyChainAnalysis(ctx, pkg.Name)
			require.NoError(t, err)
			
			// Check build integrity findings for signature validation
			hasValidSignature := true
			for _, finding := range result.BuildIntegrityFindings {
				if finding.Type == "signature_validation" && finding.Severity >= types.SeverityMedium {
					hasValidSignature = false
					break
				}
			}
			
			assert.Equal(t, tc.expectedResult, hasValidSignature)
		})
	}
}

// Helper functions for SolarWinds-style testing

func setupSolarWindsScanner(t *testing.T) *scanner.EnhancedScanner {
	// Initialize enhanced scanner with SolarWinds-specific detection capabilities
	return &scanner.EnhancedScanner{}
}

func createSolarWindsTestPackage(name, version, indicator string) *types.Package {
	pkg := &types.Package{
		Name:       name,
		Version:    version,
		Registry:   "npm",
		RiskLevel:  types.SeverityLow,
		RiskScore:  0.0,
		AnalyzedAt: time.Now(),
	}
	
	// Add indicator to metadata
	if pkg.Metadata == nil {
		pkg.Metadata = &types.PackageMetadata{}
	}
	if pkg.Metadata.Metadata == nil {
		pkg.Metadata.Metadata = make(map[string]interface{})
	}
	pkg.Metadata.Metadata["build_indicator"] = indicator
	
	return pkg
}

func createSolarWindsTestPackageWithCode(name, version, code string) *types.Package {
	pkg := createSolarWindsTestPackage(name, version, "malicious_code")
	pkg.Metadata.Metadata["malicious_code"] = code
	return pkg
}

func createSolarWindsTestPackageWithNetworkActivity(name, version, networkPattern string) *types.Package {
	pkg := createSolarWindsTestPackage(name, version, "network_activity")
	pkg.Metadata.Metadata["network_pattern"] = networkPattern
	return pkg
}

func createSolarWindsTestPackageWithSignature(name, version string, validSignature bool) *types.Package {
	pkg := createSolarWindsTestPackage(name, version, "signature_check")
	pkg.Metadata.Metadata["signature_valid"] = validSignature
	return pkg
}

func createSolarWindsTestPackageWithDependencies(name, version string, deps []string) *types.Package {
	pkg := createSolarWindsTestPackage(name, version, "dependency_analysis")
	pkg.Dependencies = make([]types.Dependency, len(deps))
	
	for i, dep := range deps {
		pkg.Dependencies[i] = types.Dependency{
			Name:     dep,
			Version:  "latest",
			Registry: "npm",
			Direct:   true,
		}
	}
	
	return pkg
}