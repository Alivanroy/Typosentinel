package benchmarks

import (
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func BenchmarkDetectEnhanced(b *testing.B) {
	etd := detector.NewEnhancedTyposquattingDetector()
	cases := []types.Dependency{
		{Name: "expresss", Version: "1.0.0", Registry: "npm"},
		{Name: "lodahs", Version: "1.0.0", Registry: "npm"},
		{Name: "recat", Version: "1.0.0", Registry: "npm"},
		{Name: "axois", Version: "1.0.0", Registry: "npm"},
	}
	popular := []string{"express", "lodash", "react", "axios"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, dep := range cases {
			_ = etd.DetectEnhanced(dep, popular, 0.75)
		}
	}
}

func BenchmarkDetectEnhancedHomoglyphs(b *testing.B) {
	etd := detector.NewEnhancedTyposquattingDetector()
	cases := []types.Dependency{
		{Name: "еxpress", Version: "1.0.0", Registry: "npm"}, // Cyrillic e
		{Name: "1odash", Version: "1.0.0", Registry: "npm"},  // 1 vs l
		{Name: "reαct", Version: "1.0.0", Registry: "npm"},   // Greek alpha
	}
	popular := []string{"express", "lodash", "react"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, dep := range cases {
			_ = etd.DetectEnhanced(dep, popular, 0.75)
		}
	}
}

func BenchmarkDetectEnhancedSmallProject(b *testing.B) {
	etd := detector.NewEnhancedTyposquattingDetector()
	popular := []string{"express", "lodash", "react", "axios", "request", "cross-env", "node-fetch", "react-router"}
	deps := make([]types.Dependency, 50)
	for i := 0; i < len(deps); i++ {
		base := popular[i%len(popular)]
		name := base
		if i%10 == 0 {
			name = base + "s"
		}
		deps[i] = types.Dependency{Name: name, Version: "1.0.0", Registry: "npm"}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, dep := range deps {
			_ = etd.DetectEnhanced(dep, popular, 0.75)
		}
	}
}

func BenchmarkDetectEnhancedMediumProject(b *testing.B) {
	etd := detector.NewEnhancedTyposquattingDetector()
	popular := []string{"express", "lodash", "react", "axios", "request", "cross-env", "node-fetch", "react-router"}
	deps := make([]types.Dependency, 200)
	for i := 0; i < len(deps); i++ {
		base := popular[i%len(popular)]
		name := base
		if i%10 == 0 {
			name = base + "s"
		}
		deps[i] = types.Dependency{Name: name, Version: "1.0.0", Registry: "npm"}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, dep := range deps {
			_ = etd.DetectEnhanced(dep, popular, 0.75)
		}
	}
}
