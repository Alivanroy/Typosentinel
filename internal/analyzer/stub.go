package analyzer

import (
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/registry"
)

// NewStub creates a minimal analyzer wired to a default detector engine
func NewStub() *Analyzer {
	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{Enabled: true, Threshold: 0.8, MaxDistance: 2, CheckSimilarNames: true, CheckHomoglyphs: true},
		Scanner:       &config.ScannerConfig{MaxConcurrency: 4, IncludeDevDeps: true},
	}
	return &Analyzer{
		config:     cfg,
		detector:   detector.New(cfg),
		registries: make(map[string]registry.Connector),
		stubRepo:   NewStubRepo(),
	}
}
