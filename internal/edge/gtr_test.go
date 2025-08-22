package edge

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGTRAlgorithm(t *testing.T) {
	tests := []struct {
		name   string
		config *types.Config
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   true,
		},
		{
			name:   "valid config",
			config: &types.Config{},
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
		name           string
		pkg            *types.Package
		expectedScore  float64
		expectedError  bool
		minConfidence  float64
	}{
		{
			name: "legitimate package",
			pkg: &types.Package{
				Name:     "react",
				Version:  "18.2.0",
				Registry: "npm",
				Metadata: map[string]interface{}{
					"downloads": 50000000,
					"author":    "Facebook",
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
				Metadata: map[string]interface{}{
					"downloads": 100,
					"author":    "unknown",
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
				Metadata: map[string]interface{}{
					"downloads": 50,
					"author":    "malicious",
				},
			},
			expectedScore: 0.9,
			expectedError: false,
			minConfidence: 0.8,
		},
		{
			name:          "nil package",
			pkg:           nil,
			expectedScore: 0.0,
			expectedError: true,
		},
	}

	gtr := NewGTRAlgorithm(nil)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := gtr.AnalyzePackage(ctx, tt.pkg)

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)
			assert.GreaterOrEqual(t, result.ThreatScore, tt.expectedScore-0.2)
			assert.LessOrEqual(t, result.ThreatScore, tt.expectedScore+0.2)
			assert.GreaterOrEqual(t, result.Confidence, tt.minConfidence)
			assert.Equal(t, "GTR", result.Algorithm)
			assert.NotEmpty(t, result.Details)
		})
	}
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

	results, err := gtr.AnalyzeBatch(ctx, packages)
	require.NoError(t, err)
	assert.Len(t, results, 3)

	for i, result := range results {
		assert.NotNil(t, result)
		assert.Equal(t, packages[i].Name, result.PackageName)
		assert.Equal(t, "GTR", result.Algorithm)
		assert.GreaterOrEqual(t, result.ThreatScore, 0.0)
		assert.LessOrEqual(t, result.ThreatScore, 1.0)
		assert.GreaterOrEqual(t, result.Confidence, 0.0)
		assert.LessOrEqual(t, result.Confidence, 1.0)
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
	result, err := gtr.AnalyzePackage(ctx, pkg)
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

	results := make([]*types.ThreatAnalysisResult, len(packages))
	errors := make([]error, len(packages))

	// Run concurrent analysis
	for i, pkg := range packages {
		go func(index int, p *types.Package) {
			results[index], errors[index] = gtr.AnalyzePackage(ctx, p)
		}(i, pkg)
	}

	// Wait for all goroutines to complete
	time.Sleep(2 * time.Second)

	// Verify results
	for i := 0; i < len(packages); i++ {
		assert.NoError(t, errors[i])
		assert.NotNil(t, results[i])
		assert.Equal(t, packages[i].Name, results[i].PackageName)
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
			result, err := gtr.AnalyzePackage(ctx, tt.pkg)
			// Should handle edge cases gracefully
			if err != nil {
				assert.Error(t, err)
			} else {
				assert.NotNil(t, result)
				assert.GreaterOrEqual(t, result.ThreatScore, 0.0)
				assert.LessOrEqual(t, result.ThreatScore, 1.0)
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
		Metadata: map[string]interface{}{
			"downloads": 1000000,
			"author":    "test-author",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gtr.AnalyzePackage(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}