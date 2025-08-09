package security

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	threatint "github.com/Alivanroy/Typosentinel/internal/threat_intelligence"
	"github.com/Alivanroy/Typosentinel/pkg/logger"

	_ "github.com/mattn/go-sqlite3"
)

// TestThreatDBFilterSQLInjection verifies that ThreatDatabase search filters are protected against SQL injection
func TestThreatDBFilterSQLInjection(t *testing.T) {
	// Initialize real ThreatDatabase (uses SQLite file)
	log := logger.New()
	td := threatint.NewThreatDatabase(log)
	ctx := context.Background()
	if err := td.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize threat database: %v", err)
	}
	defer func() {
		_ = td.Close()
		_ = os.Remove("threat_intelligence.db")
	}()

	// Insert sample threats using the store API
	now := time.Now()
	threat1 := &threatint.ThreatIntelligence{
		ID:              "threat-1",
		Source:          "osv",
		Type:            "vulnerability",
		Severity:        "high",
		PackageName:     "leftpad",
		Ecosystem:       "npm",
		Description:     "Test desc",
		Indicators:      []threatint.ThreatIndicator{},
		References:      []string{},
		Tags:            []string{},
		ConfidenceLevel: 0.9,
		FirstSeen:       now.Add(-24 * time.Hour),
		LastSeen:        now.Add(-1 * time.Hour),
		Metadata:        map[string]interface{}{},
	}
	if err := td.StoreThreat(ctx, threat1); err != nil {
		t.Fatalf("Failed to store threat-1: %v", err)
	}

	threat2 := &threatint.ThreatIntelligence{
		ID:              "threat-2",
		Source:          "ghsa",
		Type:            "typosquatting",
		Severity:        "medium",
		PackageName:     "reqest",
		Ecosystem:       "pypi",
		Description:     "Another desc",
		Indicators:      []threatint.ThreatIndicator{},
		References:      []string{},
		Tags:            []string{},
		ConfidenceLevel: 0.7,
		FirstSeen:       now.Add(-48 * time.Hour),
		LastSeen:        now.Add(-2 * time.Hour),
		Metadata:        map[string]interface{}{},
	}
	if err := td.StoreThreat(ctx, threat2); err != nil {
		t.Fatalf("Failed to store threat-2: %v", err)
	}

	// Open a handle to the same DB file for structural checks
	checkDB, err := sql.Open("sqlite3", "threat_intelligence.db")
	if err != nil {
		t.Fatalf("Failed to open DB for checks: %v", err)
	}
	defer checkDB.Close()

	testCases := []struct {
		name   string
		query  *threatint.ThreatQuery
		check  string
	}{
		{
			name:  "PackageName injection",
			query: &threatint.ThreatQuery{PackageName: "leftpad' OR '1'='1", Limit: 10},
			check: "Should not bypass WHERE condition",
		},
		{
			name:  "Ecosystem injection",
			query: &threatint.ThreatQuery{Ecosystem: "npm' UNION SELECT name FROM sqlite_master --", Limit: 10},
			check: "Should not execute UNION",
		},
		{
			name:  "ThreatType injection with DROP",
			query: &threatint.ThreatQuery{ThreatType: "vulnerability; DROP TABLE threats; --", Limit: 10},
			check: "Should not execute DROP TABLE",
		},
		{
			name:  "Severity boolean injection",
			query: &threatint.ThreatQuery{Severity: "high' OR 1=1 --", Limit: 10},
			check: "Should not alter WHERE logic",
		},
		{
			name:  "Source injection",
			query: &threatint.ThreatQuery{Source: "osv'; SELECT 1; --", Limit: 10},
			check: "Should not execute stacked queries",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := td.SearchThreats(ctx, tc.query)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// All injections should produce zero results because values are treated as data
			if res.Total != 0 || len(res.Threats) != 0 {
				t.Errorf("%s: expected 0 results, got total=%d len=%d", tc.check, res.Total, len(res.Threats))
			}

			// Table should still exist
			var cnt int
			if err := checkDB.QueryRow("SELECT COUNT(*) FROM threats").Scan(&cnt); err != nil {
				t.Errorf("%s: table integrity check failed: %v", tc.check, err)
			}
		})
	}
}