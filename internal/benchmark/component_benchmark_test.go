package benchmark

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
			CommonTypos:         true,
			LevenshteinEnabled:  true,
		},
	}

	engine := detector.NewEngine(cfg)

	testPackages := []string{
		"lodash", "express", "react", "angular", "vue",
		"webpack", "babel", "eslint", "prettier", "typescript",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pkg := range testPackages {
			_, err := engine.AnalyzePackage(pkg, "1.0.0")
			if err != nil {
				b.Fatalf("AnalyzePackage failed: %v", err)
			}
		}
	}
}

// BenchmarkDetectorTyposquatting tests typosquatting detection performance
func BenchmarkDetectorTyposquatting(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
			CommonTypos:         true,
			LevenshteinEnabled:  true,
		},
	}

	engine := detector.NewEngine(cfg)

	// Test with suspicious package names
	suspiciousPackages := []string{
		"lodahs", "expres", "reakt", "angualr", "veu",
		"webpakc", "bable", "eslint", "pretier", "typescirpt",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pkg := range suspiciousPackages {
			threats := engine.DetectTyposquatting(pkg)
			_ = threats // Use the result to prevent optimization
		}
	}
}

// BenchmarkDetectorSimilarity tests similarity calculation performance
func BenchmarkDetectorSimilarity(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
	}

	engine := detector.NewEngine(cfg)

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
			similarity := engine.CalculateSimilarity(pair[0], pair[1])
			_ = similarity // Use the result to prevent optimization
		}
	}
}

// BenchmarkStaticAnalyzer tests static analysis performance
func BenchmarkStaticAnalyzer(b *testing.B) {
	cfg := &config.Config{
		Static: config.StaticConfig{
			Enabled: true,
			Timeout: 30 * time.Second,
		},
	}

	analyzer := static.NewAnalyzer(cfg)
	testDir := createTestProjectWithScripts(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := analyzer.Analyze(ctx, testDir)
			if err != nil {
				b.Fatalf("Static analysis failed: %v", err)
			}
	}
}

// BenchmarkStaticAnalyzerPackage tests static package analysis performance
func BenchmarkStaticAnalyzerPackage(b *testing.B) {
	cfg := &config.Config{
		Static: config.StaticConfig{
			Enabled: true,
			Timeout: 30 * time.Second,
		},
	}

	analyzer := static.NewAnalyzer(cfg)

	testPackage := &types.Package{
		Name:        "test-package",
		Version:     "1.0.0",
		Description: "A test package for benchmarking",
		Author:      "Test Author",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := analyzer.AnalyzePackage(ctx, testPackage)
		if err != nil {
			b.Fatalf("Package analysis failed: %v", err)
		}
	}
}

// BenchmarkMLAnalyzer tests ML analysis performance
func BenchmarkMLAnalyzer(b *testing.B) {
	cfg := &config.Config{
		ML: config.MLConfig{
			Enabled:   true,
			ModelPath: "test-model",
			Timeout:   30 * time.Second,
		},
	}

	analyzer := ml.NewAnalyzer(cfg)

	testPackage := &types.Package{
		Name:        "suspicious-package",
		Version:     "1.0.0",
		Description: "A potentially suspicious package",
		Author:      "Unknown Author",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := analyzer.AnalyzePackage(ctx, testPackage)
		if err != nil {
			b.Fatalf("ML analysis failed: %v", err)
		}
	}
}

// BenchmarkMLAnalyzerDirectory tests ML directory analysis performance
func BenchmarkMLAnalyzerDirectory(b *testing.B) {
	cfg := &config.Config{
		ML: config.MLConfig{
			Enabled:   true,
			ModelPath: "test-model",
			Timeout:   30 * time.Second,
		},
	}

	analyzer := ml.NewAnalyzer(cfg)
	testDir := createTestProjectWithScripts(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := analyzer.Analyze(ctx, testDir)
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
			CommonTypos:         true,
			LevenshteinEnabled:  true,
		},
	}

	engine := detector.NewEngine(cfg)

	testPackages := []string{
		"lodash", "express", "react", "angular", "vue",
		"webpack", "babel", "eslint", "prettier", "typescript",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, pkg := range testPackages {
				_, err := engine.AnalyzePackage(pkg, "1.0.0")
				if err != nil {
					b.Fatalf("AnalyzePackage failed: %v", err)
				}
			}
		}
	})
}

// BenchmarkLevenshteinDistance tests Levenshtein distance calculation performance
func BenchmarkLevenshteinDistance(b *testing.B) {
	cfg := &config.Config{}
	engine := detector.NewEngine(cfg)

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
			distance := engine.LevenshteinDistance(pair[0], pair[1])
			_ = distance // Use the result to prevent optimization
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

	engine := detector.NewEngine(cfg)

	testThreats := []types.Threat{
		{Type: "typosquatting", Severity: "high", Confidence: 0.9},
		{Type: "suspicious", Severity: "medium", Confidence: 0.7},
		{Type: "malicious", Severity: "critical", Confidence: 0.95},
	}

	testReputation := &types.Reputation{
		Score:       0.3,
		TrustLevel:  "low",
		Sources:     []string{"test-source"},
		LastUpdated: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		riskScore := engine.CalculateRiskScore(testThreats, testReputation)
		_ = riskScore // Use the result to prevent optimization
	}
}

// BenchmarkRecommendationGeneration tests recommendation generation performance
func BenchmarkRecommendationGeneration(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
	}

	engine := detector.NewEngine(cfg)

	testThreats := []types.Threat{
		{Type: "typosquatting", Severity: "high", Confidence: 0.9},
		{Type: "suspicious", Severity: "medium", Confidence: 0.7},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recommendations := engine.GenerateRecommendations(testThreats, 0.8)
		_ = recommendations // Use the result to prevent optimization
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