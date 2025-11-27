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
