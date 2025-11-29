package scanner_test

import (
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestScannerHandlesMultipleLockfiles(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := `{"name":"multi","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644))
	lockJSON := `{"name":"multi","version":"1.0.0","lockfileVersion":2,"packages":{"":{"version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0"}}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockJSON), 0o644))
	yarnLock := "left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz\"\n  integrity \"sha512-abc\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(yarnLock), 0o644))
	cfg := config.NewDefaultConfig()
	s, err := scanner.New(cfg)
	require.NoError(t, err)
	_, err = s.ScanProject(dir)
	require.NoError(t, err)
}
