// Package detector provides typosquatting and threat detection algorithms.
package detector

import (
	"context"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

type Options struct {
	SimilarityThreshold float64
	DeepAnalysis        bool
}

type Engine struct {
	enhancedDetector *EnhancedTyposquattingDetector
}

func New(cfg *config.Config) *Engine {
	return &Engine{
		enhancedDetector: NewEnhancedTyposquattingDetector(),
	}
}

func (e *Engine) Version() string { return "1.0.0" }

type CheckPackageResult struct {
	Threats  []types.Threat
	Warnings []types.Warning
}

func (e *Engine) CheckPackage(ctx context.Context, name, registry string) (*CheckPackageResult, error) {
	// For single package checks, we need a list of popular packages to compare against
	// This is a simplified implementation - in production, you'd fetch this from a database
	popularPackages := []string{
		"express", "lodash", "react", "angular", "vue", "webpack", "babel", "typescript",
		"eslint", "jest", "mocha", "chai", "sinon", "cross-env", "nodemon", "pm2",
	}

	// Create a dependency for analysis
	dep := types.Dependency{
		Name:     name,
		Version:  "unknown",
		Registry: registry,
	}

	threats, warnings := e.AnalyzeDependency(dep, popularPackages, &Options{
		SimilarityThreshold: 0.75,
		DeepAnalysis:        true,
	})

	return &CheckPackageResult{
		Threats:  threats,
		Warnings: warnings,
	}, nil
}

func (e *Engine) AnalyzeDependency(dep types.Dependency, popularPackages []string, options *Options) ([]types.Threat, []types.Warning) {
	if e.enhancedDetector == nil {
		return []types.Threat{}, []types.Warning{}
	}

	// Use enhanced detector for typosquatting analysis
	threshold := 0.75 // default threshold
	if options != nil && options.SimilarityThreshold > 0 {
		threshold = options.SimilarityThreshold
	}

	threats := e.enhancedDetector.DetectEnhanced(dep, popularPackages, threshold)

	return threats, []types.Warning{}
}

type EnhancedSupplyChainDetector struct{}

func NewEnhancedSupplyChainDetector() *EnhancedSupplyChainDetector {
	return &EnhancedSupplyChainDetector{}
}

type EnhancedSupplyChainResult struct {
	Package           string
	Registry          string
	ThreatType        string
	Severity          string
	ConfidenceScore   float64
	IsFiltered        bool
	Recommendations   []string
	SupplyChainRisk   float64
	FalsePositiveRisk float64
	FilterReasons     []string
	Evidence          []string
}

func (d *EnhancedSupplyChainDetector) DetectThreats(ctx context.Context, pkgs []types.Package) ([]EnhancedSupplyChainResult, error) {
	return nil, nil
}
