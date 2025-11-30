package benchmarks

import (
	"context"
	"fmt"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/edge"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BenchmarkRUNT analyzes performance of the RUNT algorithm
func BenchmarkRUNT(b *testing.B) {
	config := &edge.RUNTConfig{
		OverallThreshold:      0.8,
		MinPackageLength:      3,
		MaxPackageLength:      50,
		EnableUnicodeAnalysis: true,
	}
	algo := edge.NewRUNTAlgorithm(config)
	ctx := context.Background()

	// Setup test data
	smallBatch := make([]string, 10)
	mediumBatch := make([]string, 100)
	largeBatch := make([]string, 1000)

	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("package-%d", i)
		if i < 10 {
			smallBatch[i] = name
		}
		if i < 100 {
			mediumBatch[i] = name
		}
		largeBatch[i] = name
	}

	b.Run("SmallBatch_10", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = algo.Analyze(ctx, smallBatch)
		}
	})

	b.Run("MediumBatch_100", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = algo.Analyze(ctx, mediumBatch)
		}
	})

	b.Run("LargeBatch_1000", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = algo.Analyze(ctx, largeBatch)
		}
	})
}

// BenchmarkDIRT analyzes performance of the DIRT algorithm
func BenchmarkDIRT(b *testing.B) {
	config := &edge.DIRTConfig{
		MaxPropagationDepth:   10,
		HighRiskThreshold:     0.7,
		EnableCascadeAnalysis: true,
	}
	algo := edge.NewDIRTAlgorithm(config)
	ctx := context.Background()

	pkg := &types.Package{
		Name:     "critical-service",
		Version:  "1.0.0",
		Registry: "npm",
	}

	b.Run("AnalyzeWithCriticality", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = algo.AnalyzeWithCriticality(ctx, pkg, edge.CriticalityCritical)
		}
	})
}

// BenchmarkGTR analyzes performance of the GTR algorithm
func BenchmarkGTR(b *testing.B) {
	config := &edge.GTRConfig{
		MaxTraversalDepth:  5,
		MinRiskThreshold:   0.6,
		EnablePathAnalysis: true,
	}
	algo := edge.NewGTRAlgorithm(config)
	ctx := context.Background()

	// Create a simulated dependency graph
	// A -> B -> C -> D -> E
	root := "root-package"

	// Since GTR relies on external connectors for real graph resolution,
	// we are benchmarking the core analysis logic overhead here.
	// For a full graph benchmark, we'd need to mock the connector.

	b.Run("CoreAnalysis", func(b *testing.B) {
		packages := []string{root}
		for i := 0; i < b.N; i++ {
			_, _ = algo.Analyze(ctx, packages)
		}
	})
}
