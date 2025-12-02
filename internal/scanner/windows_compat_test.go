package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsDirectoryScanning(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping Windows-specific test on non-Windows OS")
	}

	// Create a temp directory
	tmpDir, err := os.MkdirTemp("", "typosentinel-windows-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create a package.json to make it a valid project
	err = os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("{}"), 0644)
	require.NoError(t, err)

	// Create a directory that might be problematic (e.g. hidden)
	hiddenDir := filepath.Join(tmpDir, ".hidden")
	err = os.Mkdir(hiddenDir, 0755)
	require.NoError(t, err)

	// Create a directory with restricted permissions (read-only)
	// On Windows, 0444 might not prevent reading directory content, but let's try.
	lockedDir := filepath.Join(tmpDir, "locked_dir")
	err = os.Mkdir(lockedDir, 0444) // Read-only
	require.NoError(t, err)

	// Create a config
	// We manually construct it since NewDefaultConfig might not be exported or available
	cfg := &config.Config{
		Scanner: &config.ScannerConfig{
			RespectGitignore: true,
			IncludeDevDeps:   false,
		},
	}

	scanner, err := New(cfg)
	require.NoError(t, err)

	// Scan
	result, err := scanner.ScanProject(tmpDir)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
