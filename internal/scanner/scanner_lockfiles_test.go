package scanner_test

import (
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestScannerHandlesLockfilesPresence(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644))
	cfg := config.NewDefaultConfig()
	s, err := scanner.New(cfg)
	require.NoError(t, err)
	_, err = s.ScanProject(dir)
	require.NoError(t, err)
}
