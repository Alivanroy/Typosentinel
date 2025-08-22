package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ExtremeTestCase represents the most challenging detection scenarios
type ExtremeTestCase struct {
	Name                string
	PackageName         string
	LegitimateTarget    string
	AttackVector        string
	ObfuscationLevel    int // 1-10 scale
	ExpectedDetection   bool
	ExpectedConfidence  float64
	Description         string
	Payload             map[string]interface{}
}

// TestGTRExtremeEdgeCases tests GTR algorithm against the most sophisticated attacks
func TestGTRExtremeEdgeCases(t *testing.T) {
	extremeCases := []ExtremeTestCase{
		{
			Name:               "Unicode Homoglyph Steganography",
			PackageName:        "rеact", // Cyrillic 'е' instead of Latin 'e'
			LegitimateTarget:   "react",
			AttackVector:       "unicode_homoglyph_steganography",
			ObfuscationLevel:   9,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.85,
			Description:        "Uses visually identical Unicode characters with hidden steganographic payload",
			Payload: map[string]interface{}{
				"hidden_chars": []string{"\u200B", "\u200C", "\u200D"}, // Zero-width characters
				"encoding":     "utf8_bom_steganography",
			},
		},
		{
			Name:               "Polyglot Package Injection",
			PackageName:        "lodash-utils",
			LegitimateTarget:   "lodash",
			AttackVector:       "polyglot_injection",
			ObfuscationLevel:   10,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.75,
			Description:        "Package that appears legitimate but contains polyglot code execution",
			Payload: map[string]interface{}{
				"languages": []string{"javascript", "python", "bash", "powershell"},
				"execution_contexts": []string{"node", "browser", "worker", "service_worker"},
			},
		},
		{
			Name:               "Quantum-Resistant Obfuscation",
			PackageName:        "express-middleware",
			LegitimateTarget:   "express",
			AttackVector:       "quantum_resistant_obfuscation",
			ObfuscationLevel:   10,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.70,
			Description:        "Uses quantum-resistant cryptographic obfuscation techniques",
			Payload: map[string]interface{}{
				"crypto_scheme": "lattice_based_obfuscation",
				"key_size":      4096,
				"rounds":        256,
			},
		},
		{
			Name:               "Metamorphic Code Evolution",
			PackageName:        "webpack-plugin",
			LegitimateTarget:   "webpack",
			AttackVector:       "metamorphic_evolution",
			ObfuscationLevel:   9,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.80,
			Description:        "Code that evolves its structure while maintaining malicious functionality",
			Payload: map[string]interface{}{
				"evolution_generations": 50,
				"mutation_rate":         0.15,
				"fitness_function":      "stealth_maximization",
			},
		},
		{
			Name:               "Temporal Logic Bomb",
			PackageName:        "moment-timezone",
			LegitimateTarget:   "moment",
			AttackVector:       "temporal_logic_bomb",
			ObfuscationLevel:   8,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.85,
			Description:        "Malicious code activated by complex temporal conditions",
			Payload: map[string]interface{}{
				"trigger_conditions": []string{
					"lunar_eclipse_2024",
					"prime_number_timestamp",
					"fibonacci_sequence_match",
				},
				"activation_probability": 0.001,
			},
		},
	}

	for _, testCase := range extremeCases {
		t.Run(testCase.Name, func(t *testing.T) {
			// Initialize GTR algorithm
			gtr := edge.NewGTRAlgorithm(nil)
			ctx := context.Background()

			// Create test package
			testPkg := &types.Package{
				Name:    testCase.PackageName,
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Name:        testCase.PackageName,
					Version:     "1.0.0",
					Description: fmt.Sprintf("Test package for %s", testCase.Description),
					Metadata: map[string]interface{}{
						"attack_vector":      testCase.AttackVector,
						"obfuscation_level": testCase.ObfuscationLevel,
						"payload":            testCase.Payload,
						"legitimate_target":  testCase.LegitimateTarget,
					},
				},
			}

			// Run analysis
			result, err := gtr.Analyze(ctx, testPkg)
			require.NoError(t, err, "GTR analysis should not fail")
			require.NotNil(t, result, "GTR result should not be nil")

			// Validate detection
			if testCase.ExpectedDetection {
				assert.True(t, result.ThreatScore > 0.5, 
					"Should detect threat for %s (score: %.3f)", testCase.Name, result.ThreatScore)
				assert.GreaterOrEqual(t, result.Confidence, testCase.ExpectedConfidence,
					"Confidence should meet minimum threshold for %s", testCase.Name)
			} else {
				assert.LessOrEqual(t, result.ThreatScore, 0.5,
					"Should not detect threat for %s (score: %.3f)", testCase.Name, result.ThreatScore)
			}

			// Validate attack vector detection
			assert.Contains(t, result.AttackVectors, testCase.AttackVector,
				"Should identify correct attack vector for %s", testCase.Name)

			// Performance validation
			assert.Less(t, result.ProcessingTime.Milliseconds(), int64(5000),
				"Analysis should complete within 5 seconds for %s", testCase.Name)
		})
	}
}

// TestRUNTAdvancedSimilarityEvasion tests RUNT against sophisticated similarity evasion
func TestRUNTAdvancedSimilarityEvasion(t *testing.T) {
	advancedEvasionCases := []ExtremeTestCase{
		{
			Name:               "Semantic Preserving Transformation",
			PackageName:        "reactjs", // Semantically similar but different
			LegitimateTarget:   "react",
			AttackVector:       "semantic_preservation",
			ObfuscationLevel:   7,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.75,
			Description:        "Maintains semantic meaning while evading string similarity",
			Payload: map[string]interface{}{
				"semantic_vectors": []float64{0.95, 0.87, 0.92, 0.89},
				"word_embeddings":  "bert_large_uncased",
			},
		},
		{
			Name:               "Phonetic Camouflage",
			PackageName:        "noad-js", // Sounds like "node-js"
			LegitimateTarget:   "nodejs",
			AttackVector:       "phonetic_camouflage",
			ObfuscationLevel:   6,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.80,
			Description:        "Uses phonetically similar but visually different names",
			Payload: map[string]interface{}{
				"phonetic_algorithm": "double_metaphone",
				"sound_similarity":   0.95,
			},
		},
		{
			Name:               "Keyboard Layout Exploitation",
			PackageName:        "lodadh", // 's' -> 'd' on QWERTY
			LegitimateTarget:   "lodash",
			AttackVector:       "keyboard_layout_exploit",
			ObfuscationLevel:   5,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.85,
			Description:        "Exploits common keyboard layout typing errors",
			Payload: map[string]interface{}{
				"layout_type":     "qwerty",
				"error_patterns": []string{"adjacent_key", "shift_error"},
			},
		},
	}

	for _, testCase := range advancedEvasionCases {
		t.Run(testCase.Name, func(t *testing.T) {
			// Initialize RUNT algorithm
			runt := edge.NewRUNTAlgorithm(nil)
			ctx := context.Background()

			// Create test package
			testPkg := &types.Package{
				Name:    testCase.PackageName,
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Name:        testCase.PackageName,
					Version:     "1.0.0",
					Description: fmt.Sprintf("Advanced evasion test: %s", testCase.Description),
					Metadata: map[string]interface{}{
						"legitimate_target": testCase.LegitimateTarget,
						"attack_vector":     testCase.AttackVector,
						"payload":           testCase.Payload,
					},
				},
			}

			// Run RUNT analysis
			result, err := runt.Analyze(ctx, testPkg)
			require.NoError(t, err, "RUNT analysis should not fail")
			require.NotNil(t, result, "RUNT result should not be nil")

			// Validate sophisticated detection
			if testCase.ExpectedDetection {
				assert.True(t, result.ThreatScore > 0.6,
					"RUNT should detect advanced evasion for %s (score: %.3f)", 
					testCase.Name, result.ThreatScore)
				assert.GreaterOrEqual(t, result.Confidence, testCase.ExpectedConfidence,
					"RUNT confidence should meet threshold for %s", testCase.Name)
			}

			// Validate similarity metrics detection
			assert.NotEmpty(t, result.Findings, "Should have detailed findings for %s", testCase.Name)
			assert.Contains(t, result.AttackVectors, testCase.AttackVector,
				"Should identify attack vector for %s", testCase.Name)
		})
	}
}

// TestAICCAttestationForgery tests AICC against sophisticated attestation attacks
func TestAICCAttestationForgery(t *testing.T) {
	attestationAttacks := []ExtremeTestCase{
		{
			Name:               "Quantum Signature Forgery",
			PackageName:        "crypto-utils",
			LegitimateTarget:   "crypto",
			AttackVector:       "quantum_signature_forgery",
			ObfuscationLevel:   10,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.90,
			Description:        "Uses quantum computing to forge digital signatures",
			Payload: map[string]interface{}{
				"quantum_algorithm": "shor_variant",
				"key_size":          2048,
				"forge_success":     true,
			},
		},
		{
			Name:               "Blockchain Attestation Manipulation",
			PackageName:        "web3-connector",
			LegitimateTarget:   "web3",
			AttackVector:       "blockchain_attestation_manipulation",
			ObfuscationLevel:   9,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.85,
			Description:        "Manipulates blockchain-based attestation records",
			Payload: map[string]interface{}{
				"blockchain_type": "ethereum",
				"smart_contract":  "0x1234567890abcdef",
				"gas_limit":       21000,
			},
		},
		{
			Name:               "Zero-Knowledge Proof Bypass",
			PackageName:        "zk-proof-lib",
			LegitimateTarget:   "zkproof",
			AttackVector:       "zk_proof_bypass",
			ObfuscationLevel:   10,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.80,
			Description:        "Bypasses zero-knowledge proof verification",
			Payload: map[string]interface{}{
				"proof_system": "groth16",
				"circuit_size":  1000000,
				"bypass_method": "trusted_setup_compromise",
			},
		},
	}

	for _, testCase := range attestationAttacks {
		t.Run(testCase.Name, func(t *testing.T) {
			// Initialize AICC algorithm
			aicc := edge.NewAICCAlgorithm(nil)
			ctx := context.Background()

			// Create test package with forged attestations
			testPkg := &types.Package{
				Name:    testCase.PackageName,
				Version: "1.0.0",
				Metadata: &types.PackageMetadata{
					Name:        testCase.PackageName,
					Version:     "1.0.0",
					Description: fmt.Sprintf("Attestation attack test: %s", testCase.Description),
					Metadata: map[string]interface{}{
						"attestations": map[string]interface{}{
							"forged":        true,
							"attack_vector": testCase.AttackVector,
							"payload":       testCase.Payload,
						},
						"legitimate_target": testCase.LegitimateTarget,
					},
				},
			}

			// Run AICC analysis
			result, err := aicc.Analyze(ctx, testPkg)
			require.NoError(t, err, "AICC analysis should not fail")
			require.NotNil(t, result, "AICC result should not be nil")

			// Validate attestation forgery detection
			if testCase.ExpectedDetection {
				assert.True(t, result.ThreatScore > 0.7,
					"AICC should detect attestation forgery for %s (score: %.3f)",
					testCase.Name, result.ThreatScore)
				assert.GreaterOrEqual(t, result.Confidence, testCase.ExpectedConfidence,
					"AICC confidence should be high for %s", testCase.Name)
			}

			// Validate specific attestation findings
			assert.NotEmpty(t, result.Findings, "Should have attestation findings for %s", testCase.Name)
			assert.Contains(t, result.AttackVectors, testCase.AttackVector,
				"Should identify attestation attack vector for %s", testCase.Name)
		})
	}
}

// TestDIRTSupplyChainCascade tests DIRT against complex supply chain attacks
func TestDIRTSupplyChainCascade(t *testing.T) {
	cascadeAttacks := []ExtremeTestCase{
		{
			Name:               "Multi-Tier Dependency Poisoning",
			PackageName:        "build-tools",
			LegitimateTarget:   "build",
			AttackVector:       "multi_tier_poisoning",
			ObfuscationLevel:   8,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.85,
			Description:        "Cascading attack through multiple dependency tiers",
			Payload: map[string]interface{}{
				"cascade_depth":    5,
				"infection_rate":   0.75,
				"propagation_time": "24h",
			},
		},
		{
			Name:               "Transitive Vulnerability Amplification",
			PackageName:        "security-middleware",
			LegitimateTarget:   "security",
			AttackVector:       "transitive_amplification",
			ObfuscationLevel:   9,
			ExpectedDetection:  true,
			ExpectedConfidence: 0.80,
			Description:        "Amplifies vulnerabilities through transitive dependencies",
			Payload: map[string]interface{}{
				"amplification_factor": 3.5,
				"vulnerability_chain": []string{"CVE-2024-0001", "CVE-2024-0002"},
				"impact_radius":        50,
			},
		},
	}

	for _, testCase := range cascadeAttacks {
		t.Run(testCase.Name, func(t *testing.T) {
			// Initialize DIRT algorithm
			dirt := edge.NewDIRTAlgorithm(nil)
			ctx := context.Background()

			// Create test package with complex dependencies
			testPkg := &types.Package{
				Name:    testCase.PackageName,
				Version: "1.0.0",
				Dependencies: []types.Dependency{
					{Name: "malicious-dep-1", Version: "1.0.0"},
					{Name: "malicious-dep-2", Version: "2.1.0"},
					{Name: "legitimate-dep", Version: "3.0.0"},
				},
				Metadata: &types.PackageMetadata{
					Name:        testCase.PackageName,
					Version:     "1.0.0",
					Description: fmt.Sprintf("Supply chain cascade test: %s", testCase.Description),
					Metadata: map[string]interface{}{
						"supply_chain_attack": testCase.Payload,
						"attack_vector":       testCase.AttackVector,
						"legitimate_target":   testCase.LegitimateTarget,
					},
				},
			}

			// Run DIRT analysis
			result, err := dirt.Analyze(ctx, testPkg)
			require.NoError(t, err, "DIRT analysis should not fail")
			require.NotNil(t, result, "DIRT result should not be nil")

			// Validate cascade detection
			if testCase.ExpectedDetection {
				assert.True(t, result.ThreatScore > 0.6,
					"DIRT should detect supply chain cascade for %s (score: %.3f)",
					testCase.Name, result.ThreatScore)
				assert.GreaterOrEqual(t, result.Confidence, testCase.ExpectedConfidence,
					"DIRT confidence should meet threshold for %s", testCase.Name)
			}

			// Validate dependency impact analysis
			assert.NotEmpty(t, result.Findings, "Should have dependency findings for %s", testCase.Name)
			assert.Contains(t, result.AttackVectors, testCase.AttackVector,
				"Should identify supply chain attack vector for %s", testCase.Name)
		})
	}
}

// TestTimingAttackResistance tests algorithms against timing-based attacks
func TestTimingAttackResistance(t *testing.T) {
	timingTests := []struct {
		name      string
		algorithm string
		packages  []string
		maxTime   time.Duration
	}{
		{
			name:      "GTR Timing Consistency",
			algorithm: "gtr",
			packages:  []string{"react", "rеact", "r3act", "re4ct"},
			maxTime:   100 * time.Millisecond,
		},
		{
			name:      "RUNT Timing Consistency",
			algorithm: "runt",
			packages:  []string{"lodash", "lodadh", "l0dash", "lodash-utils"},
			maxTime:   200 * time.Millisecond,
		},
		{
			name:      "AICC Timing Consistency",
			algorithm: "aicc",
			packages:  []string{"crypto", "crypt0", "crypto-js", "cryptography"},
			maxTime:   150 * time.Millisecond,
		},
		{
			name:      "DIRT Timing Consistency",
			algorithm: "dirt",
			packages:  []string{"express", "expr3ss", "express-js", "expressjs"},
			maxTime:   300 * time.Millisecond,
		},
	}

	for _, tt := range timingTests {
		t.Run(tt.name, func(t *testing.T) {
			var timings []time.Duration
			ctx := context.Background()

			for _, pkgName := range tt.packages {
				testPkg := &types.Package{
					Name:    pkgName,
					Version: "1.0.0",
					Metadata: &types.PackageMetadata{
						Name:    pkgName,
						Version: "1.0.0",
					},
				}

				start := time.Now()
				
				// Run algorithm based on type
				switch tt.algorithm {
				case "gtr":
					gtr := edge.NewGTRAlgorithm(nil)
					_, err := gtr.Analyze(ctx, testPkg)
					require.NoError(t, err)
				case "runt":
					runt := edge.NewRUNTAlgorithm(nil)
					_, err := runt.Analyze(ctx, testPkg)
					require.NoError(t, err)
				case "aicc":
					aicc := edge.NewAICCAlgorithm(nil)
					_, err := aicc.Analyze(ctx, testPkg)
					require.NoError(t, err)
				case "dirt":
					dirt := edge.NewDIRTAlgorithm(nil)
					_, err := dirt.Analyze(ctx, testPkg)
					require.NoError(t, err)
				}

				elapsed := time.Since(start)
				timings = append(timings, elapsed)

				// Validate individual timing
				assert.Less(t, elapsed, tt.maxTime,
					"Analysis of %s should complete within %v (took %v)",
					pkgName, tt.maxTime, elapsed)
			}

			// Validate timing consistency (no timing attacks)
			var totalTime time.Duration
			for _, timing := range timings {
				totalTime += timing
			}
			avgTime := totalTime / time.Duration(len(timings))

			// Check that no timing deviates more than 50% from average
			for i, timing := range timings {
				deviation := float64(timing-avgTime) / float64(avgTime)
				if deviation < 0 {
					deviation = -deviation
				}
				assert.Less(t, deviation, 0.5,
					"Timing for package %s should not deviate more than 50%% from average (deviation: %.2f%%)",
					tt.packages[i], deviation*100)
			}
		})
	}
}

// TestConcurrentAnalysisStability tests algorithms under concurrent load
func TestConcurrentAnalysisStability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent stability test in short mode")
	}

	concurrentTests := []struct {
		name         string
		algorithm    string
		concurrency  int
		iterations   int
		expectedRate float64 // success rate
	}{
		{"GTR Concurrent Stability", "gtr", 10, 100, 0.95},
		{"RUNT Concurrent Stability", "runt", 8, 80, 0.95},
		{"AICC Concurrent Stability", "aicc", 12, 120, 0.95},
		{"DIRT Concurrent Stability", "dirt", 6, 60, 0.95},
	}

	for _, tt := range concurrentTests {
		t.Run(tt.name, func(t *testing.T) {
			successCount := 0
			totalCount := tt.concurrency * tt.iterations
			resultChan := make(chan bool, totalCount)

			// Launch concurrent analyses
			for i := 0; i < tt.concurrency; i++ {
				go func(workerID int) {
					for j := 0; j < tt.iterations; j++ {
						testPkg := &types.Package{
						Name:     fmt.Sprintf("test-pkg-%d-%d", workerID, j),
						Version:  "1.0.0",
						Metadata: &types.PackageMetadata{
							Name:    fmt.Sprintf("test-pkg-%d-%d", workerID, j),
							Version: "1.0.0",
						},
					}

						ctx := context.Background()
						success := true

						// Run algorithm
						switch tt.algorithm {
						case "gtr":
							gtr := edge.NewGTRAlgorithm(nil)
							_, err := gtr.Analyze(ctx, testPkg)
							if err != nil {
								success = false
							}
						case "runt":
							runt := edge.NewRUNTAlgorithm(nil)
							_, err := runt.Analyze(ctx, testPkg)
							if err != nil {
								success = false
							}
						case "aicc":
							aicc := edge.NewAICCAlgorithm(nil)
							_, err := aicc.Analyze(ctx, testPkg)
							if err != nil {
								success = false
							}
						case "dirt":
							dirt := edge.NewDIRTAlgorithm(nil)
							_, err := dirt.Analyze(ctx, testPkg)
							if err != nil {
								success = false
							}
						}

						resultChan <- success
					}
				}(i)
			}

			// Collect results
			for i := 0; i < totalCount; i++ {
				if <-resultChan {
					successCount++
				}
			}

			// Validate success rate
			actualRate := float64(successCount) / float64(totalCount)
			assert.GreaterOrEqual(t, actualRate, tt.expectedRate,
				"Success rate should be at least %.2f%% (actual: %.2f%%)",
				tt.expectedRate*100, actualRate*100)
		})
	}
}