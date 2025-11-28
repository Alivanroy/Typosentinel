package output

import (
	"encoding/json"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
)

type CycloneDXBOM struct {
	BomFormat   string                 `json:"bomFormat"`
	SpecVersion string                 `json:"specVersion"`
	Version     int                    `json:"version"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Components  []CycloneDXComponent   `json:"components"`
}

type CycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

type CycloneDXFormatter struct{}

func NewCycloneDXFormatter() *CycloneDXFormatter { return &CycloneDXFormatter{} }

func (f *CycloneDXFormatter) Format(res *scanner.ScanResults, opts *FormatterOptions) ([]byte, error) {
	bom := CycloneDXBOM{BomFormat: "CycloneDX", SpecVersion: "1.5", Version: 1, Metadata: map[string]interface{}{"timestamp": time.Now().UTC().Format(time.RFC3339)}}
	seen := make(map[string]bool)
	for _, r := range res.Results {
		if r.Package == nil {
			continue
		}
		key := r.Package.Name + "@" + r.Package.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		bom.Components = append(bom.Components, CycloneDXComponent{Type: "library", Name: r.Package.Name, Version: r.Package.Version})
	}
	return json.MarshalIndent(bom, "", opts.Indent)
}
