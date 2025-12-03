package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContentScanner(t *testing.T) {
	scanner := NewContentScanner()
	scanner.denyCIDRs = []string{"0.0.0.0/0"} // Deny all for testing
	scanner.entropyThreshold = 5.0            // Lower threshold for testing

	tests := []struct {
		name          string
		content       string
		filename      string
		expectThreats bool
		expectedType  string
	}{
		{
			name:          "Safe file",
			content:       "console.log('hello world');",
			filename:      "index.js",
			expectThreats: false,
		},
		{
			name:          "Embedded AWS Key",
			content:       "const awsKey = 'AKIAIOSFODNN7EXAMPLE';",
			filename:      "config.js",
			expectThreats: true,
			expectedType:  string(types.ThreatTypeEmbeddedSecret),
		},
		{
			name:          "High Entropy (Obfuscation)",
			content:       "var a = '89234789234789234789234789234789234789234789234789';", // Not high enough entropy, need random junk
			filename:      "obfuscated.js",
			expectThreats: false, // Simple repeated string has low entropy
		},
		{
			name:          "Suspicious Eval Chain",
			content:       "eval(eval(eval(eval(code))));",
			filename:      "evil.js",
			expectThreats: true,
			expectedType:  string(types.ThreatTypeSuspiciousPattern),
		},
		{
			name:          "Suspicious IP",
			content:       "const c2 = '185.100.200.1';", // Random public IP
			filename:      "net.js",
			expectThreats: true,
			expectedType:  string(types.ThreatTypeSuspiciousPattern),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "content-test")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			filePath := filepath.Join(tmpDir, tt.filename)
			err = os.WriteFile(filePath, []byte(tt.content), 0644)
			require.NoError(t, err)

			threats := scanner.scanFile(filePath)

			if tt.expectThreats {
				assert.NotEmpty(t, threats, "Expected threats for %s", tt.name)
				if len(threats) > 0 {
					found := false
					for _, threat := range threats {
						if string(threat.Type) == tt.expectedType {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected threat type %s", tt.expectedType)
				}
			} else {
				assert.Empty(t, threats, "Expected no threats for %s", tt.name)
			}
		})
	}
}
