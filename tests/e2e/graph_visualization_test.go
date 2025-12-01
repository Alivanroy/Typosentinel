//go:build realworld

package e2e

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGraphVisualization(t *testing.T) {
	// Setup test workspace
	wd, err := filepath.Abs("../..")
	require.NoError(t, err)

	tests := []struct {
		name             string
		format           string
		expectedStart    string
		expectedEnd      string
		expectedContains []string
	}{
		{
			name:          "DOT Output",
			format:        "dot",
			expectedStart: "digraph DependencyGraph {",
			expectedEnd:   "}",
			expectedContains: []string{
				"rankdir=LR;",
				"subgraph cluster_root",
				"subgraph cluster_metadata",
			},
		},
		{
			name:          "SVG Output",
			format:        "svg",
			expectedStart: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
			expectedEnd:   "</svg>",
			expectedContains: []string{
				"<svg xmlns=\"http://www.w3.org/2000/svg\"",
				"Dependency Graph:",
				"filter id=\"shadow\"",
			},
		},
		{
			name:          "Mermaid Output",
			format:        "mermaid",
			expectedStart: "graph LR",
			expectedEnd:   "", // Mermaid doesn't have a strict end marker
			expectedContains: []string{
				"classDef critical",
				"subgraph Threats",
				"root(\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use "scan" command which supports the graph output formats via outputScanResult
			// We use "main.go" as target to avoid directory scanning panic on Windows environment
			cmd := exec.Command("go", "run", ".", "scan", "main.go", "--output", tt.format)
			cmd.Dir = wd

			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Logf("Command failed: %v\nOutput: %s", err, string(out))
				// If it failed due to network or other non-graph issues, we might still get partial output or error
				// But for graph generation, it usually happens after scan.
			}

			outputStr := string(out)

			// Check start
			if !strings.HasPrefix(strings.TrimSpace(outputStr), tt.expectedStart) {
				// It might have log messages before. Look for the start string.
				if !strings.Contains(outputStr, tt.expectedStart) {
					t.Errorf("Output does not contain expected start: %s", tt.expectedStart)
				}
			}

			// Check end
			if tt.expectedEnd != "" && !strings.Contains(outputStr, tt.expectedEnd) {
				t.Errorf("Output does not contain expected end: %s", tt.expectedEnd)
			}

			// Check contains
			for _, s := range tt.expectedContains {
				if !strings.Contains(outputStr, s) {
					t.Errorf("Output missing expected string: %s", s)
				}
			}
		})
	}
}
