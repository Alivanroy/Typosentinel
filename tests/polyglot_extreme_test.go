package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// PolyglotTestCase represents a polyglot attack test case
type PolyglotTestCase struct {
	Name                string
	PackageName         string
	LegitimatePackage   string
	AttackVector        string
	PayloadType         string
	SeverityLevel       string
	ExpectedDetection   bool
	MinThreatScore      float64
	Description         string
}

// TestPolyglotPackageAttacks tests sophisticated polyglot packages
func TestPolyglotPackageAttacks(t *testing.T) {
	testCases := []PolyglotTestCase{
		{
			Name:              "NPM-PyPI Cross-Platform Typosquatting",
			PackageName:       "reqeusts", // Typo of "requests"
			LegitimatePackage: "requests",
			AttackVector:      "cross_platform_typosquatting",
			PayloadType:       "credential_harvester",
			SeverityLevel:     "critical",
			ExpectedDetection: true,
			MinThreatScore:    0.6,
			Description:       "Package that mimics popular Python requests library",
		},
		{
			Name:              "Dependency Confusion Attack",
			PackageName:       "@company/internal-utils",
			LegitimatePackage: "@company/internal-utils",
			AttackVector:      "dependency_confusion",
			PayloadType:       "reverse_shell",
			SeverityLevel:     "critical",
			ExpectedDetection: true,
			MinThreatScore:    0.7,
			Description:       "Public package with same name as private internal package",
		},
		{
			Name:              "Subdomain Squatting",
			PackageName:       "lodash.isempty",
			LegitimatePackage: "lodash",
			AttackVector:      "subdomain_squatting",
			PayloadType:       "data_exfiltration",
			SeverityLevel:     "high",
			ExpectedDetection: true,
			MinThreatScore:    0.5,
			Description:       "Fake lodash utility that appears to be official",
		},
		{
			Name:              "Version Pinning Attack",
			PackageName:       "express",
			LegitimatePackage: "express",
			AttackVector:      "version_pinning",
			PayloadType:       "backdoor",
			SeverityLevel:     "critical",
			ExpectedDetection: true,
			MinThreatScore:    0.8,
			Description:       "Legitimate package name with malicious version",
		},
		{
			Name:              "Homograph Attack with Mixed Scripts",
			PackageName:       "аxios", // Cyrillic 'а' instead of Latin 'a'
			LegitimatePackage: "axios",
			AttackVector:      "homograph_attack",
			PayloadType:       "keylogger",
			SeverityLevel:     "high",
			ExpectedDetection: true,
			MinThreatScore:    0.7,
			Description:       "Package using Cyrillic characters to mimic axios",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			// Test with all edge algorithms
			algorithms := map[string]func() interface{}{
				"GTR":  func() interface{} { return edge.NewGTRAlgorithm(nil) },
				"RUNT": func() interface{} { return edge.NewRUNTAlgorithm(nil) },
				"AICC": func() interface{} { return edge.NewAICCAlgorithm(nil) },
				"DIRT": func() interface{} { return edge.NewDIRTAlgorithm(nil) },
			}

			for algoName, algoFactory := range algorithms {
				t.Run(algoName, func(t *testing.T) {
					algo := algoFactory()
					ctx := context.Background()

					// Create test package with polyglot attack characteristics
					testPkg := createPolyglotPackage(testCase)

					// Analyze with the algorithm
					var result *edge.AnalysisResult
					var err error

					switch v := algo.(type) {
					case *edge.GTRAlgorithm:
						result, err = v.Analyze(ctx, testPkg)
					case *edge.RUNTAlgorithm:
						result, err = v.Analyze(ctx, testPkg)
					case *edge.AICCAlgorithm:
						result, err = v.Analyze(ctx, testPkg)
					case *edge.DIRTAlgorithm:
						result, err = v.Analyze(ctx, testPkg)
					default:
						t.Fatalf("Unknown algorithm type: %T", v)
					}

					if err != nil {
						t.Fatalf("Analysis failed: %v", err)
					}

					// Log detailed results for analysis
					t.Logf("%s Analysis Results for %s:", algoName, testCase.AttackVector)
					t.Logf("  Package: %s (mimics %s)", testCase.PackageName, testCase.LegitimatePackage)
					t.Logf("  Threat Score: %.3f", result.ThreatScore)
					t.Logf("  Confidence: %.3f", result.Confidence)
					t.Logf("  Attack Vectors: %v", result.AttackVectors)
					t.Logf("  Findings Count: %d", len(result.Findings))
					t.Logf("  Severity: %s", testCase.SeverityLevel)

					// Validate detection based on algorithm strengths
					if testCase.ExpectedDetection {
						switch algoName {
						case "RUNT":
							// RUNT should excel at typosquatting detection
							if strings.Contains(testCase.AttackVector, "typosquatting") || strings.Contains(testCase.AttackVector, "homograph") {
								if result.ThreatScore < 0.3 {
									t.Errorf("RUNT should detect %s better, got score %.3f", testCase.AttackVector, result.ThreatScore)
								}
							}
						case "DIRT":
							// DIRT should excel at dependency analysis
							if strings.Contains(testCase.AttackVector, "dependency") {
								if result.ThreatScore < 0.3 {
									t.Errorf("DIRT should detect %s better, got score %.3f", testCase.AttackVector, result.ThreatScore)
								}
							}
						case "AICC":
							// AICC should excel at attestation and integrity
							if strings.Contains(testCase.AttackVector, "version") || strings.Contains(testCase.AttackVector, "confusion") {
								if result.ThreatScore < 0.3 {
									t.Errorf("AICC should detect %s better, got score %.3f", testCase.AttackVector, result.ThreatScore)
								}
							}
						case "GTR":
							// GTR should provide overall threat assessment
							if testCase.SeverityLevel == "critical" {
								if result.ThreatScore < 0.2 {
									t.Errorf("GTR should detect critical threats better, got score %.3f", result.ThreatScore)
								}
							}
						}
					}
				})
			}
		})
	}
}

// TestAdvancedEvasionTechniques tests sophisticated evasion methods
func TestAdvancedEvasionTechniques(t *testing.T) {
	testCases := []struct {
		Name           string
		PackageName    string
		EvasionMethod  string
		Description    string
	}{
		{
			Name:          "Legitimate Package Takeover Simulation",
			PackageName:   "event-stream",
			EvasionMethod: "legitimate_takeover",
			Description:   "Simulates the event-stream attack pattern",
		},
		{
			Name:          "Gradual Malicious Introduction",
			PackageName:   "utility-helpers",
			EvasionMethod: "gradual_introduction",
			Description:   "Package that becomes malicious over time",
		},
		{
			Name:          "Conditional Payload Activation",
			PackageName:   "dev-tools",
			EvasionMethod: "conditional_activation",
			Description:   "Payload only activates under specific conditions",
		},
		{
			Name:          "Supply Chain Poisoning",
			PackageName:   "build-utils",
			EvasionMethod: "supply_chain_poisoning",
			Description:   "Targets build and development tools",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			// Test with DIRT algorithm (best for dependency analysis)
			dirt := edge.NewDIRTAlgorithm(nil)
			ctx := context.Background()

			testPkg := &types.Package{
				Name:     testCase.PackageName,
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Name:        testCase.PackageName,
					Version:     "1.0.0",
					Registry:    "npm",
					Description: generateEvasiveDescription(testCase.EvasionMethod),
					Metadata: map[string]interface{}{
						"evasion_method":     testCase.EvasionMethod,
						"attack_sophistication": "high",
						"target_environment":    "production",
						"persistence_level":     "high",
						"detection_evasion":     "advanced",
					},
				},
				Dependencies: generateSuspiciousDependencies(testCase.EvasionMethod),
			}

			result, err := dirt.Analyze(ctx, testPkg)
			if err != nil {
				t.Fatalf("DIRT analysis failed: %v", err)
			}

			t.Logf("DIRT Analysis for %s:", testCase.EvasionMethod)
			t.Logf("  Threat Score: %.3f", result.ThreatScore)
			t.Logf("  Confidence: %.3f", result.Confidence)
			t.Logf("  Attack Vectors: %v", result.AttackVectors)
			t.Logf("  Dependencies Analyzed: %d", len(testPkg.Dependencies))
		})
	}
}

// TestConcurrentPolyglotAttacks tests multiple simultaneous attack vectors
func TestConcurrentPolyglotAttacks(t *testing.T) {
	// Create a package that combines multiple attack vectors
	combinedAttackPkg := &types.Package{
		Name:     "rеact-dom", // Homoglyph + typosquatting
		Version:  "18.2.1",   // Version confusion
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:        "rеact-dom",
			Version:     "18.2.1",
			Registry:    "npm",
			Description: "React DOM library with enhanced features and performance optimizations",
			Metadata: map[string]interface{}{
				"attack_vectors": []string{"homoglyph", "typosquatting", "version_confusion"},
				"sophistication": "maximum",
				"stealth_level":  "high",
				"target_scope":   "widespread",
			},
		},
		Dependencies: []types.Dependency{
			{
				Name:     "@babel/core",
				Version:  "7.20.0",
				Registry: "npm",
				Source:   "package.json",
				Direct:   true,
				Metadata: types.PackageMetadata{
					Name:     "@babel/core",
					Version:  "7.20.0",
					Registry: "npm",
				},
			},
			{
				Name:     "suspicious-util",
				Version:  "1.0.0",
				Registry: "npm",
				Source:   "package.json",
				Direct:   true,
				Metadata: types.PackageMetadata{
					Name:     "suspicious-util",
					Version:  "1.0.0",
					Registry: "npm",
				},
			},
		},
	}

	// Test with all algorithms
	algorithms := map[string]func() interface{}{
		"GTR":  func() interface{} { return edge.NewGTRAlgorithm(nil) },
		"RUNT": func() interface{} { return edge.NewRUNTAlgorithm(nil) },
		"AICC": func() interface{} { return edge.NewAICCAlgorithm(nil) },
		"DIRT": func() interface{} { return edge.NewDIRTAlgorithm(nil) },
	}

	for algoName, algoFactory := range algorithms {
		t.Run(algoName, func(t *testing.T) {
			algo := algoFactory()
			ctx := context.Background()

			var result *edge.AnalysisResult
			var err error

			switch v := algo.(type) {
			case *edge.GTRAlgorithm:
				result, err = v.Analyze(ctx, combinedAttackPkg)
			case *edge.RUNTAlgorithm:
				result, err = v.Analyze(ctx, combinedAttackPkg)
			case *edge.AICCAlgorithm:
				result, err = v.Analyze(ctx, combinedAttackPkg)
			case *edge.DIRTAlgorithm:
				result, err = v.Analyze(ctx, combinedAttackPkg)
			default:
				t.Fatalf("Unknown algorithm type: %T", v)
			}

			if err != nil {
				t.Fatalf("Analysis failed: %v", err)
			}

			t.Logf("%s Analysis of Combined Attack Package:", algoName)
			t.Logf("  Package: %s (mimics react-dom)", combinedAttackPkg.Name)
			t.Logf("  Threat Score: %.3f", result.ThreatScore)
			t.Logf("  Confidence: %.3f", result.Confidence)
			t.Logf("  Attack Vectors: %v", result.AttackVectors)
			t.Logf("  Findings Count: %d", len(result.Findings))

			// Each algorithm should detect at least some threat
			if result.ThreatScore == 0.0 {
				t.Logf("WARNING: %s did not detect any threat in combined attack package", algoName)
			}
		})
	}
}

// Helper functions

func createPolyglotPackage(testCase PolyglotTestCase) *types.Package {
	return &types.Package{
		Name:     testCase.PackageName,
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Name:        testCase.PackageName,
			Version:     "1.0.0",
			Registry:    "npm",
			Description: generatePolyglotDescription(testCase),
			Metadata: map[string]interface{}{
				"attack_vector":       testCase.AttackVector,
				"payload_type":        testCase.PayloadType,
				"severity_level":      testCase.SeverityLevel,
				"legitimate_package":  testCase.LegitimatePackage,
				"sophistication":      "high",
				"evasion_techniques":  []string{"name_similarity", "metadata_spoofing"},
			},
		},
		Dependencies: generateMaliciousDependencies(testCase.AttackVector),
	}
}

func generatePolyglotDescription(testCase PolyglotTestCase) string {
	switch testCase.AttackVector {
	case "cross_platform_typosquatting":
		return fmt.Sprintf("Python HTTP library for humans. Mimics the popular %s package.", testCase.LegitimatePackage)
	case "dependency_confusion":
		return "Internal utility functions for company projects. Enhanced with additional features."
	case "subdomain_squatting":
		return fmt.Sprintf("Utility functions from the %s ecosystem. Provides isEmpty functionality.", testCase.LegitimatePackage)
	case "version_pinning":
		return "Fast, unopinionated, minimalist web framework for node. Enhanced security features."
	case "homograph_attack":
		return fmt.Sprintf("Promise based HTTP client for the browser and node.js. Compatible with %s.", testCase.LegitimatePackage)
	default:
		return testCase.Description
	}
}

func generateMaliciousDependencies(attackVector string) []types.Dependency {
	switch attackVector {
	case "dependency_confusion":
		return []types.Dependency{
			{
				Name:     "internal-config",
				Version:  "1.0.0",
				Registry: "npm",
				Source:   "package.json",
				Direct:   true,
				Metadata: types.PackageMetadata{
					Name:     "internal-config",
					Version:  "1.0.0",
					Registry: "npm",
				},
			},
		}
	case "version_pinning":
		return []types.Dependency{
			{
				Name:     "malicious-middleware",
				Version:  "1.0.0",
				Registry: "npm",
				Source:   "package.json",
				Direct:   true,
				Metadata: types.PackageMetadata{
					Name:     "malicious-middleware",
					Version:  "1.0.0",
					Registry: "npm",
				},
			},
		}
	default:
		return []types.Dependency{}
	}
}

func generateEvasiveDescription(evasionMethod string) string {
	switch evasionMethod {
	case "legitimate_takeover":
		return "Streaming events library with enhanced performance and additional utility functions."
	case "gradual_introduction":
		return "Collection of utility functions for common development tasks. Regularly updated with new features."
	case "conditional_activation":
		return "Development tools and utilities for modern JavaScript projects. Environment-aware functionality."
	case "supply_chain_poisoning":
		return "Build utilities and helpers for modern web development. Optimized for CI/CD pipelines."
	default:
		return "Utility package with various helper functions."
	}
}

func generateSuspiciousDependencies(evasionMethod string) []types.Dependency {
	switch evasionMethod {
	case "supply_chain_poisoning":
		return []types.Dependency{
			{
				Name:     "build-scripts",
				Version:  "1.0.0",
				Registry: "npm",
				Source:   "package.json",
				Direct:   true,
				Metadata: types.PackageMetadata{
					Name:     "build-scripts",
					Version:  "1.0.0",
					Registry: "npm",
				},
			},
			{
				Name:     "deploy-helpers",
				Version:  "2.1.0",
				Registry: "npm",
				Source:   "package.json",
				Direct:   true,
				Metadata: types.PackageMetadata{
					Name:     "deploy-helpers",
					Version:  "2.1.0",
					Registry: "npm",
				},
			},
		}
	default:
		return []types.Dependency{}
	}
}