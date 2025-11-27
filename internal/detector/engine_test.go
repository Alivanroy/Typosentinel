package detector

import (
	"context"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestEngine_New(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := New(cfg)

	if engine == nil {
		t.Fatal("Expected engine to be created, got nil")
	}

	if engine.enhancedDetector == nil {
		t.Error("Expected enhanced detector to be initialized")
	}
}

func TestEngine_Version(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := New(cfg)

	version := engine.Version()
	if version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", version)
	}
}

func TestEngine_CheckPackage(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := New(cfg)
	ctx := context.Background()

	tests := []struct {
		name           string
		packageName    string
		registry       string
		expectThreats  bool
		expectedThreat string
	}{
		{
			name:           "Typosquat of express",
			packageName:    "expresss",
			registry:       "npm",
			expectThreats:  true,
			expectedThreat: "express",
		},
		{
			name:          "Clean package name",
			packageName:   "express",
			registry:      "npm",
			expectThreats: false,
		},
		{
			name:           "Typosquat of cross-env",
			packageName:    "crossenv",
			registry:       "npm",
			expectThreats:  true,
			expectedThreat: "cross-env",
		},
		{
			name:          "Non-existent package",
			packageName:   "nonexistentpackage123",
			registry:      "npm",
			expectThreats: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.CheckPackage(ctx, tt.packageName, tt.registry)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.expectThreats {
				if len(result.Threats) == 0 {
					t.Error("Expected threats but got none")
				} else {
					found := false
					for _, threat := range result.Threats {
						if threat.SimilarTo == tt.expectedThreat {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected threat similar to %s, but not found", tt.expectedThreat)
					}
				}
			} else {
				if len(result.Threats) > 0 {
					t.Errorf("Expected no threats but got %d", len(result.Threats))
				}
			}
		})
	}
}

func TestEngine_AnalyzeDependency(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := New(cfg)

	popularPackages := []string{
		"express", "lodash", "react", "angular", "vue",
	}

	tests := []struct {
		name          string
		dependency    types.Dependency
		threshold     float64
		expectThreats bool
	}{
		{
			name: "Typosquat with high threshold",
			dependency: types.Dependency{
				Name:     "expresss",
				Version:  "1.0.0",
				Registry: "npm",
			},
			threshold:     0.8,
			expectThreats: true,
		},
		{
			name: "Typosquat with low threshold",
			dependency: types.Dependency{
				Name:     "expr3ss",
				Version:  "1.0.0",
				Registry: "npm",
			},
			threshold:     0.6,
			expectThreats: true,
		},
		{
			name: "Clean package",
			dependency: types.Dependency{
				Name:     "express",
				Version:  "1.0.0",
				Registry: "npm",
			},
			threshold:     0.8,
			expectThreats: false,
		},
		{
			name: "Non-popular package",
			dependency: types.Dependency{
				Name:     "mypackage123",
				Version:  "1.0.0",
				Registry: "npm",
			},
			threshold:     0.8,
			expectThreats: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &Options{
				SimilarityThreshold: tt.threshold,
				DeepAnalysis:        true,
			}

			threats, warnings := engine.AnalyzeDependency(tt.dependency, popularPackages, options)

			if tt.expectThreats {
				if len(threats) == 0 {
					t.Error("Expected threats but got none")
				}
			} else {
				if len(threats) > 0 {
					t.Errorf("Expected no threats but got %d", len(threats))
				}
			}

			// Warnings should be empty in current implementation
			if len(warnings) != 0 {
				t.Errorf("Expected no warnings but got %d", len(warnings))
			}
		})
	}
}

func TestEngine_AnalyzeDependency_NilOptions(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := New(cfg)

	popularPackages := []string{"express", "lodash"}
	dependency := types.Dependency{
		Name:     "expresss",
		Version:  "1.0.0",
		Registry: "npm",
	}

	threats, warnings := engine.AnalyzeDependency(dependency, popularPackages, nil)

	// Should still work with nil options (uses defaults)
	if len(threats) == 0 {
		t.Error("Expected threats with nil options")
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings but got %d", len(warnings))
	}
}

func TestEngine_AnalyzeDependency_EmptyPopularPackages(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := New(cfg)

	dependency := types.Dependency{
		Name:     "expresss",
		Version:  "1.0.0",
		Registry: "npm",
	}

	options := &Options{
		SimilarityThreshold: 0.8,
		DeepAnalysis:        true,
	}

	threats, warnings := engine.AnalyzeDependency(dependency, []string{}, options)

	// Should return no threats when no popular packages to compare against
	if len(threats) != 0 {
		t.Errorf("Expected no threats with empty popular packages, got %d", len(threats))
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings but got %d", len(warnings))
	}
}

func TestEngine_EnhancedSupplyChainDetector(t *testing.T) {
	detector := NewEnhancedSupplyChainDetector()
	if detector == nil {
		t.Fatal("Expected EnhancedSupplyChainDetector to be created")
	}

	ctx := context.Background()
	pkgs := []types.Package{
		{Name: "express", Version: "1.0.0", Registry: "npm"},
	}

	result, err := detector.DetectThreats(ctx, pkgs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Current implementation returns nil, nil
	if result != nil {
		t.Error("Expected nil result from unimplemented detector")
	}
}