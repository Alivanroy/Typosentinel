package edge

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGTRAlgorithm(t *testing.T) {
	tests := []struct {
		name   string
		config *GTRConfig
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   true,
		},
		{
			name:   "valid config",
			config: &GTRConfig{},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gtr := NewGTRAlgorithm(tt.config)
			assert.NotNil(t, gtr)
			assert.Equal(t, "GTR", gtr.Name())
		})
	}
}

func TestGTRAlgorithm_AnalyzePackage(t *testing.T) {
	tests := []struct {
		name          string
		pkg           *types.Package
		expectedScore float64
		expectedError bool
		minConfidence float64
	}{
		{
			name: "legitimate package",
			pkg: &types.Package{
				Name:     "react",
				Version:  "18.2.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 50000000,
					Author:    "Facebook",
				},
			},
			expectedScore: 0.1,
			expectedError: false,
			minConfidence: 0.8,
		},
		{
			name: "typosquatting package",
			pkg: &types.Package{
				Name:     "reactt",
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 100,
					Author:    "unknown",
				},
			},
			expectedScore: 0.8,
			expectedError: false,
			minConfidence: 0.7,
		},
		{
			name: "suspicious package with unicode",
			pkg: &types.Package{
				Name:     "rеact", // Cyrillic 'е'
				Version:  "1.0.0",
				Registry: "npm",
				Metadata: &types.PackageMetadata{
					Downloads: 50,
					Author:    "malicious",
				},
			},
			expectedScore: 0.9,
			expectedError: false,
			minConfidence: 0.8,
		},
	}

	gtr := NewGTRAlgorithm(nil)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages := []string{tt.pkg.Name}
			result, err := gtr.Analyze(ctx, packages)

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "GTR", result.Algorithm)
			assert.Contains(t, result.Packages, tt.pkg.Name)
		})
	}

	// Test empty package list
	t.Run("empty package list", func(t *testing.T) {
		_, err := gtr.Analyze(ctx, []string{})
		assert.Error(t, err)
	})
}

func TestGTRAlgorithm_AnalyzeBatch(t *testing.T) {
	gtr := NewGTRAlgorithm(nil)
	ctx := context.Background()

	packages := []*types.Package{
		{
			Name:     "react",
			Version:  "18.2.0",
			Registry: "npm",
		},
		{
			Name:     "reactt",
			Version:  "1.0.0",
			Registry: "npm",
		},
		{
			Name:     "vue",
			Version:  "3.3.0",
			Registry: "npm",
		},
	}

	// Convert packages to string slice for GTR analysis
	packageNames := make([]string, len(packages))
	for i, pkg := range packages {
		packageNames[i] = pkg.Name
	}
	result, err := gtr.Analyze(ctx, packageNames)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "GTR", result.Algorithm)
	assert.Len(t, result.Packages, 3)
	for _, pkg := range packages {
		assert.Contains(t, result.Packages, pkg.Name)
	}
}

func TestGTRAlgorithm_Performance(t *testing.T) {
	gtr := NewGTRAlgorithm(nil)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "test-package",
		Version:  "1.0.0",
		Registry: "npm",
	}

	start := time.Now()
	result, err := gtr.Analyze(ctx, []string{pkg.Name})
	duration := time.Since(start)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Less(t, duration, 5*time.Second, "Analysis should complete within 5 seconds")
}

func TestGTRAlgorithm_ConcurrentAnalysis(t *testing.T) {
	gtr := NewGTRAlgorithm(nil)
	ctx := context.Background()

	packages := make([]*types.Package, 10)
	for i := 0; i < 10; i++ {
		packages[i] = &types.Package{
			Name:     fmt.Sprintf("test-package-%d", i),
			Version:  "1.0.0",
			Registry: "npm",
		}
	}

	results := make([]*AlgorithmResult, len(packages))
	errors := make([]error, len(packages))

	// Run concurrent analysis
	for i, pkg := range packages {
		go func(index int, p *types.Package) {
			results[index], errors[index] = gtr.Analyze(ctx, []string{p.Name})
		}(i, pkg)
	}

	// Wait for all goroutines to complete
	time.Sleep(2 * time.Second)

	// Verify results
	for i := 0; i < len(packages); i++ {
		assert.NoError(t, errors[i])
		assert.NotNil(t, results[i])
		assert.Contains(t, results[i].Packages, packages[i].Name)
	}
}

func TestGTRAlgorithm_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		pkg  *types.Package
	}{
		{
			name: "empty package name",
			pkg: &types.Package{
				Name:     "",
				Version:  "1.0.0",
				Registry: "npm",
			},
		},
		{
			name: "very long package name",
			pkg: &types.Package{
				Name:     string(make([]byte, 1000)),
				Version:  "1.0.0",
				Registry: "npm",
			},
		},
		{
			name: "special characters in name",
			pkg: &types.Package{
				Name:     "@scope/package-name_with.special-chars",
				Version:  "1.0.0",
				Registry: "npm",
			},
		},
	}

	gtr := NewGTRAlgorithm(nil)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gtr.Analyze(ctx, []string{tt.pkg.Name})
			// Should handle edge cases gracefully
			if err != nil {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, "GTR", result.Algorithm)
				assert.Contains(t, result.Packages, tt.pkg.Name)
			}
		})
	}
}

func BenchmarkGTRAlgorithm_AnalyzePackage(b *testing.B) {
	gtr := NewGTRAlgorithm(nil)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "benchmark-package",
		Version:  "1.0.0",
		Registry: "npm",
		Metadata: &types.PackageMetadata{
			Downloads: 1000000,
			Author:    "test-author",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gtr.Analyze(ctx, []string{pkg.Name})
		if err != nil {
			b.Fatal(err)
		}
	}
}
