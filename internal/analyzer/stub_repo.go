package analyzer

import (
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"time"
)

type StubRepo struct{}

func NewStubRepo() *StubRepo { return &StubRepo{} }

func (s *StubRepo) Generate(dep types.Dependency) ([]types.Threat, []types.Warning) {
	var threats []types.Threat
	var warnings []types.Warning
	if dep.Registry == "npm" && dep.Name != "" {
		threats = append(threats, types.Threat{
			ID:              "STUB-NPM-001",
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeVulnerable,
			Severity:        types.SeverityMedium,
			Confidence:      0.8,
			Description:     "Stub vulnerability present for demonstration",
			Recommendation:  "Upgrade to a secure version",
			DetectedAt:      time.Now(),
			DetectionMethod: "stub_repo",
			References:      []string{"https://example.com/stub/advisory"},
		})
	}
	return threats, warnings
}
