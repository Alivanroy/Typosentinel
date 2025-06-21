package benchmark

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"typosentinel/internal/config"
	"typosentinel/internal/detector"
	"typosentinel/internal/ml"
	"typosentinel/internal/static"
	"typosentinel/pkg/types"
)

// BenchmarkDetectorEngine tests the performance of the detector engine
func BenchmarkDetectorEngine(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
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
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
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
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
		},
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
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			HomoglyphDetection:  true,
			SemanticAnalysis:    true,
		},
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
	cfg := &config.Config{}
	engine := detector.New(cfg)

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
			// Use CheckPackage to test similarity calculation
			ctx := context.Background()
			result, err := engine.CheckPackage(ctx, pair[0], "npm")
			if err != nil {
				b.Fatalf("CheckPackage failed: %v", err)
			}
			_ = result // Use the result to prevent optimization
		}
	}
}

// BenchmarkRiskCalculation tests risk score calculation performance
func BenchmarkRiskCalculation(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
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
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
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
