package detector

import (
    "context"
    "time"
    "github.com/Alivanroy/Typosentinel/internal/threat_intelligence"
    "github.com/Alivanroy/Typosentinel/pkg/types"
)

type ThreatIntelScanner struct {
    manager *threat_intelligence.ThreatIntelligenceManager
    enabled bool
}

func NewThreatIntelScanner(m *threat_intelligence.ThreatIntelligenceManager) *ThreatIntelScanner {
    return &ThreatIntelScanner{manager: m, enabled: m != nil}
}

func (s *ThreatIntelScanner) IsEnabled() bool { return s.enabled }

type ThreatIntelScanResult struct {
    Vulnerabilities []types.Vulnerability
    RiskLevel       string
}

func (s *ThreatIntelScanner) ScanPackage(ctx context.Context, name, registry, version string) (*ThreatIntelScanResult, error) {
    _ = ctx
    return &ThreatIntelScanResult{Vulnerabilities: nil, RiskLevel: "low"}, nil
}

func (s *ThreatIntelScanner) ConvertToThreats(res *ThreatIntelScanResult) []types.Threat {
    if res == nil || len(res.Vulnerabilities) == 0 { return nil }
    out := make([]types.Threat, 0, len(res.Vulnerabilities))
    for _, v := range res.Vulnerabilities {
        out = append(out, types.Threat{
            ID:              v.ID,
            Package:         v.Package,
            Type:            types.ThreatTypeVulnerable,
            Severity:        v.Severity,
            Description:     v.Description,
            CVEs:            []string{v.CVE},
            References:      v.References,
            DetectedAt:      time.Now(),
            DetectionMethod: "threat_intel_scanner",
        })
    }
    return out
}

