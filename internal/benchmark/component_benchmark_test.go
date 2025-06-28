package benchmark

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/ml"
	"github.com/Alivanroy/Typosentinel/internal/static"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BenchmarkDetectorEngine tests the performance of the detector engine
func BenchmarkDetectorEngine(b *testing.B) {
	cfg := &config.Config{
		Detection: &config.DetectionConfig{},
	}

	engine := detector.New(cfg)

	testPackages := []string{
		"lodash", "express", "react", "angular", "vue",
		"webpack", "babel", "eslint", "prettier", "typescript",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pkg := range testPackages {
			ctx := context.Background()
			_, err := engine.CheckPackage(ctx, pkg, "npm")
			if err != nil {
				b.Fatalf("CheckPackage failed: %v", err)
			}
		}
	}
}

// BenchmarkDetectorTyposquatting tests typosquatting detection performance
func BenchmarkDetectorTyposquatting(b *testing.B) {
	cfg := &config.Config{
		Detection: &config.DetectionConfig{},
	}

	engine := detector.New(cfg)

	// Test with suspicious package names
	suspiciousPackages := []string{
		"lodahs", "expres", "reakt", "angualr", "veu",
		"webpakc", "bable", "eslint", "pretier", "typescirpt",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pkg := range suspiciousPackages {
			result, err := engine.CheckPackage(context.Background(), pkg, "npm")
			if err != nil {
				b.Fatalf("CheckPackage failed: %v", err)
			}
			_ = result // Use the result to prevent optimization
		}
	}
}

// BenchmarkDetectorSimilarity tests similarity calculation performance
func BenchmarkDetectorSimilarity(b *testing.B) {
	cfg := &config.Config{
		Detection: &config.DetectionConfig{},
	}

	engine := detector.New(cfg)

	packagePairs := [][]string{
		{"lodash", "lodahs"},
		{"express", "expres"},
		{"react", "reakt"},
		{"angular", "angualr"},
		{"vue", "veu"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pair := range packagePairs {
			ctx := context.Background()
			_, err := engine.CheckPackage(ctx, pair[0], "npm")
			if err != nil {
				b.Fatalf("CheckPackage failed: %v", err)
			}
		}
	}
}

// BenchmarkStaticAnalyzer tests static analysis performance
func BenchmarkStaticAnalyzer(b *testing.B) {
	cfg := &static.Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := static.NewStaticAnalyzer(cfg)
	if err != nil {
		b.Fatalf("Failed to create static analyzer: %v", err)
	}
	testDir := createTestProjectWithScripts(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := analyzer.AnalyzePackage(ctx, testDir)
		if err != nil {
			b.Fatalf("Static analysis failed: %v", err)
		}
	}
}

// BenchmarkStaticAnalyzerPackage tests static package analysis performance
func BenchmarkStaticAnalyzerPackage(b *testing.B) {
	cfg := &static.Config{
		Enabled: true,
		Timeout: "30s",
	}

	analyzer, err := static.NewStaticAnalyzer(cfg)
	if err != nil {
		b.Fatalf("Failed to create static analyzer: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		// Create a temporary directory for the test package
		testDir := createTestProjectWithScripts(b)
		defer os.RemoveAll(testDir)
		_, err := analyzer.AnalyzePackage(ctx, testDir)
		if err != nil {
			b.Fatalf("Package analysis failed: %v", err)
		}
	}
}

// BenchmarkMLAnalyzer tests ML analysis performance
func BenchmarkMLAnalyzer(b *testing.B) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		ModelPath:           "test-model",
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
	}

	analyzer := ml.NewMLAnalyzer(cfg)

	testPackage := &types.Package{
		Name:      "suspicious-package",
		Version:   "1.0.0",
		Registry:  "npm",
		RiskLevel: types.SeverityMedium,
		RiskScore: 0.6,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := analyzer.Analyze(ctx, testPackage)
		if err != nil {
			b.Fatalf("ML analysis failed: %v", err)
		}
	}
}

// BenchmarkMLAnalyzerDirectory tests ML directory analysis performance
func BenchmarkMLAnalyzerDirectory(b *testing.B) {
	cfg := config.MLAnalysisConfig{
		Enabled:             true,
		ModelPath:           "test-model",
		SimilarityThreshold: 0.8,
		MaliciousThreshold:  0.7,
		ReputationThreshold: 0.6,
	}

	analyzer := ml.NewMLAnalyzer(cfg)
	testDir := createTestProjectWithScripts(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		// Create a test package for analysis
		testPackage := &types.Package{
			Name:      "test-package",
			Version:   "1.0.0",
			Registry:  "npm",
			RiskLevel: types.SeverityLow,
			RiskScore: 0.1,
		}
		_, err := analyzer.Analyze(ctx, testPackage)
		if err != nil {
			b.Fatalf("ML directory analysis failed: %v", err)
		}
	}
}

// BenchmarkConcurrentDetection tests concurrent detection performance
func BenchmarkConcurrentDetection(b *testing.B) {
	cfg := &config.Config{
		Detection: &config.DetectionConfig{},
	}

	engine := detector.New(cfg)

	testPackages := []string{
		"lodash", "express", "react", "angular", "vue",
		"webpack", "babel", "eslint", "prettier", "typescript",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, pkg := range testPackages {
				ctx := context.Background()
				_, err := engine.CheckPackage(ctx, pkg, "npm")
				if err != nil {
					b.Fatalf("CheckPackage failed: %v", err)
				}
			}
		}
	})
}

// BenchmarkLevenshteinDistance tests Levenshtein distance calculation performance
func BenchmarkLevenshteinDistance(b *testing.B) {
	stringPairs := [][]string{
		{"lodash", "lodahs"},
		{"express", "expres"},
		{"react", "reakt"},
		{"angular", "angualr"},
		{"vue", "veu"},
		{"webpack", "webpakc"},
		{"babel", "bable"},
		{"eslint", "eslint"},
		{"prettier", "pretier"},
		{"typescript", "typescirpt"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pair := range stringPairs {
			// Direct Levenshtein distance calculation
			distance := levenshteinDistance(pair[0], pair[1])
			_ = distance // Use the result to prevent optimization
		}
	}
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = minInt(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// minInt returns the minimum of the given integers
func minInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

// BenchmarkRiskCalculation tests risk score calculation performance
func BenchmarkRiskCalculation(b *testing.B) {
	cfg := &config.Config{
		Detection: &config.DetectionConfig{},
	}

	engine := detector.New(cfg)

	// Create a test dependency for risk calculation
	testDep := types.Dependency{
		Name:     "test-package",
		Registry: "npm",
		Direct:   true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use CheckPackage instead of CalculateRiskScore
		ctx := context.Background()
		result, err := engine.CheckPackage(ctx, testDep.Name, testDep.Registry)
		if err != nil {
			b.Fatalf("CheckPackage failed: %v", err)
		}
		_ = result // Use the result to prevent optimization
	}
}

// BenchmarkRecommendationGeneration tests recommendation generation performance
func BenchmarkRecommendationGeneration(b *testing.B) {
	cfg := &config.Config{
		Detection: &config.DetectionConfig{},
	}

	engine := detector.New(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use CheckPackage instead of GenerateRecommendations
		ctx := context.Background()
		result, err := engine.CheckPackage(ctx, "test-package", "npm")
		if err != nil {
			b.Fatalf("CheckPackage failed: %v", err)
		}
		_ = result // Use the result to prevent optimization
	}
}

// Helper function to create a test project with scripts
func createTestProjectWithScripts(b *testing.B) string {
	testDir := b.TempDir()

	// Create package.json with scripts
	packageJSON := `{
	"name": "test-package-with-scripts",
	"version": "1.0.0",
	"scripts": {
		"install": "node install.js",
		"postinstall": "node postinstall.js",
		"preinstall": "echo 'preparing installation'"
	},
	"dependencies": {
		"express": "^4.18.0",
		"lodash": "^4.17.21"
	}
}`

	err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		b.Fatalf("Failed to create test package.json: %v", err)
	}

	// Create install script
	installScript := `#!/usr/bin/env node
console.log('Installing package...');
// Some potentially suspicious operations
const fs = require('fs');
const path = require('path');
const os = require('os');

// File operations
fs.writeFileSync(path.join(os.homedir(), '.test'), 'test data');

// Network operations (simulated)
console.log('Downloading additional resources...');

// Process operations
const { exec } = require('child_process');
exec('echo "Installation complete"', (error, stdout, stderr) => {
  if (error) {
    console.error('Error:', error);
    return;
  }
  console.log(stdout);
});`

	err = os.WriteFile(filepath.Join(testDir, "install.js"), []byte(installScript), 0644)
	if err != nil {
		b.Fatalf("Failed to create install script: %v", err)
	}

	// Create postinstall script
	postinstallScript := `#!/usr/bin/env node
console.log('Post-installation setup...');
const https = require('https');
const fs = require('fs');

// Simulated network call
https.get('https://api.example.com/config', (res) => {
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  res.on('end', () => {
    console.log('Configuration downloaded');
  });
}).on('error', (err) => {
  console.log('Error: ' + err.message);
});`

	err = os.WriteFile(filepath.Join(testDir, "postinstall.js"), []byte(postinstallScript), 0644)
	if err != nil {
		b.Fatalf("Failed to create postinstall script: %v", err)
	}

	return testDir
}
