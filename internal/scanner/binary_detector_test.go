package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBinaryDetection(t *testing.T) {
	detector := NewBinaryDetector()

	tests := []struct {
		name             string
		files            map[string][]byte
		expectThreats    bool
		expectedCount    int
		expectedSeverity types.Severity
	}{
		{
			name: "No binaries",
			files: map[string][]byte{
				"index.js":     []byte("console.log('hello');"),
				"package.json": []byte("{}"),
				"README.md":    []byte("# Project"),
			},
			expectThreats: false,
		},
		{
			name: "ELF binary",
			files: map[string][]byte{
				"malware":  []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
				"index.js": []byte("console.log('hello');"),
			},
			expectThreats:    true,
			expectedCount:    1,
			expectedSeverity: types.SeverityHigh,
		},
		{
			name: "Windows PE executable",
			files: map[string][]byte{
				"evil.exe": []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"),
				"index.js": []byte("console.log('hello');"),
			},
			expectThreats:    true,
			expectedCount:    1,
			expectedSeverity: types.SeverityHigh,
		},
		{
			name: "macOS Mach-O binary",
			files: map[string][]byte{
				"binary":   []byte("\xfe\xed\xfa\xce\x00\x00\x00\x12"),
				"index.js": []byte("console.log('hello');"),
			},
			expectThreats:    true,
			expectedCount:    1,
			expectedSeverity: types.SeverityHigh,
		},
		{
			name: "Legitimate .node addon in build directory",
			files: map[string][]byte{
				"build/Release/addon.node": []byte("\x7fELF\x02\x01\x01\x00"),
				"index.js":                 []byte("console.log('hello');"),
			},
			expectThreats:    true,
			expectedCount:    1,
			expectedSeverity: types.SeverityMedium, // Lower severity in legit path
		},
		{
			name: "Script with shebang",
			files: map[string][]byte{
				"install.sh": []byte("#!/bin/bash\necho 'installing'"),
				"index.js":   []byte("console.log('hello');"),
			},
			expectThreats:    true,
			expectedCount:    1,
			expectedSeverity: types.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory
			tmpDir, err := os.MkdirTemp("", "binary-test")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			// Create test files
			for filename, content := range tt.files {
				fullPath := filepath.Join(tmpDir, filename)

				// Create parent directories if needed
				parentDir := filepath.Dir(fullPath)
				if parentDir != tmpDir {
					err := os.MkdirAll(parentDir, 0755)
					require.NoError(t, err)
				}

				err := os.WriteFile(fullPath, content, 0644)
				require.NoError(t, err)
			}

			// Run detection
			threats, err := detector.DetectBinariesInDirectory(tmpDir)
			require.NoError(t, err)

			if tt.expectThreats {
				assert.NotEmpty(t, threats, "Expected to find binary threats")

				if len(threats) > 0 {
					if tt.expectedCount > 0 {
						// Check that threat description mentions correct count
						assert.Contains(t, threats[0].Description, "executable")
					}

					if tt.expectedSeverity != 0 {
						assert.Equal(t, tt.expectedSeverity, threats[0].Severity,
							"Expected severity %s but got %s", tt.expectedSeverity, threats[0].Severity)
					}

					// Check that evidence contains file info
					assert.NotEmpty(t, threats[0].Evidence)
				}
			} else {
				assert.Empty(t, threats, "Should not detect threats in safe packages")
			}
		})
	}
}

func TestBinaryDetectorFileTypes(t *testing.T) {
	detector := NewBinaryDetector()

	tests := []struct {
		name           string
		filename       string
		content        []byte
		shouldDetect   bool
		expectedFormat string
	}{
		{
			name:           "ELF header",
			filename:       "binary",
			content:        []byte("\x7fELF"),
			shouldDetect:   true,
			expectedFormat: "ELF",
		},
		{
			name:           "PE header",
			filename:       "app.exe",
			content:        []byte("MZ"),
			shouldDetect:   true,
			expectedFormat: "PE",
		},
		{
			name:           ".dll extension",
			filename:       "library.dll",
			content:        []byte("MZ"),
			shouldDetect:   true,
			expectedFormat: "PE",
		},
		{
			name:           ".so extension only",
			filename:       "lib.so",
			content:        []byte("random content"),
			shouldDetect:   true,
			expectedFormat: "SO",
		},
		{
			name:         "Plain text file",
			filename:     "readme.txt",
			content:      []byte("This is a readme file"),
			shouldDetect: false,
		},
		{
			name:         "JavaScript file",
			filename:     "index.js",
			content:      []byte("console.log('hello');"),
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "file-type-test")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			filePath := filepath.Join(tmpDir, tt.filename)
			err = os.WriteFile(filePath, tt.content, 0644)
			require.NoError(t, err)

			format, isExec := detector.isExecutableFile(filePath)

			if tt.shouldDetect {
				assert.True(t, isExec, "Should detect %s as executable", tt.filename)
				if tt.expectedFormat != "" {
					assert.Contains(t, format.Type, tt.expectedFormat)
				}
			} else {
				assert.False(t, isExec, "Should not detect %s as executable", tt.filename)
			}
		})
	}
}
