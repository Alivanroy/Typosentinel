package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"typosentinel/internal/analyzer"
	"typosentinel/internal/config"
)

// BenchmarkBasicScan tests basic scanning performance
func BenchmarkBasicScan(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
		Scanner: config.ScannerConfig{
			IncludeDevDeps: false,
		},
	}

	analyzer, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        false,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkWithMetrics tests scanning with metrics enabled
func BenchmarkWithMetrics(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
		Scanner: config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}

	analyzer, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:           "json",
			DeepAnalysis:           true,
			IncludeDevDependencies: true,
			SimilarityThreshold:    0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkDeepAnalysis tests deep analysis performance
func BenchmarkDeepAnalysis(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.9,
		},
		Scanner: config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}

	analyzer, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        true,
			SimilarityThreshold: 0.9,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkConcurrentScans tests concurrent scanning performance
func BenchmarkConcurrentScans(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
		Scanner: config.ScannerConfig{
			IncludeDevDeps: false,
		},
	}

	analyzer, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			options := &analyzer.ScanOptions{
				OutputFormat:        "json",
				DeepAnalysis:        false,
				SimilarityThreshold: 0.8,
			}
			_, err := analyzer.Scan(testDir, options)
			if err != nil {
				b.Fatalf("Scan failed: %v", err)
			}
		}
	})
}

// BenchmarkLargeProject tests performance with larger projects
func BenchmarkLargeProject(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
		Scanner: config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}

	analyzer, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}
	testDir := createLargeTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        true,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkMemoryUsage tests memory usage during scanning
func BenchmarkMemoryUsage(b *testing.B) {
	cfg := &config.Config{
		Detection: config.DetectionConfig{
			SimilarityThreshold: 0.8,
		},
		Scanner: config.ScannerConfig{
			IncludeDevDeps: true,
		},
	}

	analyzer, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}
	testDir := createTestPackage(b)
	defer os.RemoveAll(testDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		options := &analyzer.ScanOptions{
			OutputFormat:        "json",
			DeepAnalysis:        false,
			SimilarityThreshold: 0.8,
		}
		_, err := analyzer.Scan(testDir, options)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

// BenchmarkDifferentThresholds tests performance with different similarity thresholds
func BenchmarkDifferentThresholds(b *testing.B) {
	thresholds := []float64{0.6, 0.7, 0.8, 0.9}

	for _, threshold := range thresholds {
		b.Run(fmt.Sprintf("threshold_%.1f", threshold), func(b *testing.B) {
			cfg := &config.Config{
				Detection: config.DetectionConfig{
					SimilarityThreshold: threshold,
				},
				Scanner: config.ScannerConfig{
					IncludeDevDeps: false,
				},
			}

			analyzer, err := analyzer.New(cfg)
			if err != nil {
				b.Fatalf("Failed to create analyzer: %v", err)
			}
			testDir := createTestPackage(b)
			defer os.RemoveAll(testDir)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				options := &analyzer.ScanOptions{
					OutputFormat:        "json",
					DeepAnalysis:        false,
					SimilarityThreshold: threshold,
				}
				_, err := analyzer.Scan(testDir, options)
				if err != nil {
					b.Fatalf("Scan failed: %v", err)
				}
			}
		})
	}
}

// Helper function to create a test package
func createTestPackage(b *testing.B) string {
	testDir := b.TempDir()

	// Create package.json
	packageJSON := `{
	"name": "test-package",
	"version": "1.0.0",
	"dependencies": {
		"express": "^4.18.0",
		"lodash": "^4.17.21"
	},
	"devDependencies": {
		"jest": "^29.0.0",
		"eslint": "^8.0.0"
	}
}`

	err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		b.Fatalf("Failed to create test package.json: %v", err)
	}

	return testDir
}

// Helper function to create a larger test package
func createLargeTestPackage(b *testing.B) string {
	testDir := b.TempDir()

	// Create package.json with more dependencies
	packageJSON := `{
	"name": "large-test-package",
	"version": "1.0.0",
	"dependencies": {
		"express": "^4.18.0",
		"lodash": "^4.17.21",
		"axios": "^1.0.0",
		"moment": "^2.29.0",
		"react": "^18.0.0",
		"react-dom": "^18.0.0",
		"webpack": "^5.0.0",
		"babel-core": "^6.26.3"
	},
	"devDependencies": {
		"jest": "^29.0.0",
		"eslint": "^8.0.0",
		"prettier": "^2.0.0",
		"typescript": "^4.0.0",
		"@types/node": "^18.0.0",
		"@types/react": "^18.0.0"
	}
}`

	err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		b.Fatalf("Failed to create large test package.json: %v", err)
	}

	return testDir
}

// Benchmark helper to measure time
func measureTime(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}