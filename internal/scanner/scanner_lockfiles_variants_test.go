package scanner_test

import (
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestScannerHandlesYarnLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(""), 0o644))
	cfg := config.NewDefaultConfig()
	s, err := scanner.New(cfg)
	require.NoError(t, err)
	_, err = s.ScanProject(dir)
	require.NoError(t, err)
}

func TestScannerHandlesPnpmLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(""), 0o644))
	cfg := config.NewDefaultConfig()
	s, err := scanner.New(cfg)
	require.NoError(t, err)
	_, err = s.ScanProject(dir)
	require.NoError(t, err)
}

func TestScannerHandlesPoetryLock(t *testing.T) {
	dir := t.TempDir()
	toml := `[project]
dependencies = ["requests==2.32.0", "numpy>=1.24.0"]
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(toml), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(""), 0o644))
	cfg := config.NewDefaultConfig()
	s, err := scanner.New(cfg)
	require.NoError(t, err)
	_, err = s.ScanProject(dir)
	require.NoError(t, err)
}
