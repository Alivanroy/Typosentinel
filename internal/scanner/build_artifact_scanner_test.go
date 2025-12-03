package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildArtifactScanner(t *testing.T) {
	scanner := NewBuildArtifactScanner()

	// Create temp directory structure
	tmpDir, err := os.MkdirTemp("", "build-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create build directories
	distDir := filepath.Join(tmpDir, "dist")
	nodeModulesDir := filepath.Join(tmpDir, "node_modules", "some-package")
	require.NoError(t, os.MkdirAll(distDir, 0755))
	require.NoError(t, os.MkdirAll(nodeModulesDir, 0755))

	// Create a fake PE binary (Windows executable)
	peBinary := filepath.Join(distDir, "malware.exe")
	peHeader := []byte{'M', 'Z', 0x90, 0x00}
	require.NoError(t, os.WriteFile(peBinary, peHeader, 0644))

	// Create a fake ELF binary (Linux executable)
	elfBinary := filepath.Join(nodeModulesDir, "miner.bin")
	elfHeader := []byte{0x7F, 'E', 'L', 'F'}
	require.NoError(t, os.WriteFile(elfBinary, elfHeader, 0644))

	// Create a legitimate file (should not be flagged)
	jsFile := filepath.Join(distDir, "bundle.js")
	require.NoError(t, os.WriteFile(jsFile, []byte("console.log('hello');"), 0644))

	// Run scan
	threats, err := scanner.ScanProject(tmpDir)
	require.NoError(t, err)

	// Should detect both binaries
	assert.GreaterOrEqual(t, len(threats), 2, "Should detect at least 2 binaries")

	// Verify threat types
	for _, threat := range threats {
		assert.Equal(t, "unexpected_binary", string(threat.Type))
		assert.Contains(t, []string{"medium", "high", "critical"}, threat.Severity.String())
	}
}

func TestBinaryDetection(t *testing.T) {
	scanner := NewBuildArtifactScanner()

	tests := []struct {
		name     string
		header   []byte
		expected bool
	}{
		{
			name:     "PE (Windows)",
			header:   []byte{'M', 'Z', 0x90, 0x00},
			expected: true,
		},
		{
			name:     "ELF (Linux)",
			header:   []byte{0x7F, 'E', 'L', 'F'},
			expected: true,
		},
		{
			name:     "Mach-O (macOS)",
			header:   []byte{0xCF, 0xFA, 0xED, 0xFE},
			expected: true,
		},
		{
			name:     "Text file",
			header:   []byte("console.log('test');"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "binary-test")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.Write(tt.header)
			require.NoError(t, err)
			tmpFile.Close()

			result := scanner.isBinaryFile(tmpFile.Name())
			assert.Equal(t, tt.expected, result)
		})
	}
}
