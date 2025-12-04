package output

import (
	"encoding/json"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

func TestSARIFFormatter_Format(t *testing.T) {
	res := &analyzer.ScanResult{
		Path:          "./dummy",
		TotalPackages: 2,
		Threats: []types.Threat{
			{Package: "expresss", Version: "1.0.0", Severity: types.SeverityMedium, Confidence: 0.8, Type: types.ThreatTypeTyposquatting},
		},
	}
	f := NewSARIFFormatter("", "", "", "cli")
	b, err := f.Format(res)
	if err != nil {
		t.Fatalf("format error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("json parse error: %v", err)
	}
	if _, ok := parsed["runs"]; !ok {
		t.Fatalf("missing runs field")
	}
}
