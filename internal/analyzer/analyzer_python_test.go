package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePythonRequirements(t *testing.T) {
	dir := t.TempDir()
	req := `# sample requirements
requests==2.32.0
numpy>=1.24.0; python_version>"3.8"
flask[async]==2.1.0
-e git+https://github.com/pallets/flask.git#egg=flask`
	p := filepath.Join(dir, "requirements.txt")
	require.NoError(t, os.WriteFile(p, []byte(req), 0o644))

	a := &Analyzer{}
	deps, err := a.parsePythonRequirements(p)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(deps), 3)
	for _, d := range deps {
		assert.Equal(t, "pypi", d.Registry)
	}
}

func TestParsePyprojectToml(t *testing.T) {
	dir := t.TempDir()
	toml := `
[project]
dependencies = ["requests==2.32.0", "numpy>=1.24.0"]

[tool.poetry.dependencies]
python = ">=3.8"
flask = "2.1.0"

[tool.poetry.dev-dependencies]
pytest = "7.1.0"

[tool.poetry.group.docs.dependencies]
sphinx = "5.0.0"
`
	p := filepath.Join(dir, "pyproject.toml")
	require.NoError(t, os.WriteFile(p, []byte(toml), 0o644))

	a := &Analyzer{}
	deps, err := a.parsePyprojectToml(p)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(deps), 4)
}

func TestDetectFileType(t *testing.T) {
	a := &Analyzer{}
	ft, reg := a.detectFileType("/path/to/package.json")
	assert.Equal(t, "npm", ft)
	assert.Equal(t, "npm", reg)
	ft, reg = a.detectFileType("/path/to/requirements.txt")
	assert.Equal(t, "python", ft)
	assert.Equal(t, "pypi", reg)
	ft, reg = a.detectFileType("/path/to/go.mod")
	assert.Equal(t, "go", ft)
	assert.Equal(t, "go", reg)
	ft, reg = a.detectFileType("/path/to/pom.xml")
	assert.Equal(t, "maven", ft)
	assert.Equal(t, "maven", reg)
}

func TestDiscoverDependencyFiles(t *testing.T) {
	dir := t.TempDir()
	files := []string{"package.json", "requirements.txt", "go.mod", "pom.xml"}
	for _, f := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o644))
	}
	a := &Analyzer{}
	opts := &ScanOptions{AllowEmptyProjects: true}
	discovered, err := a.discoverDependencyFiles(dir, opts)
	require.NoError(t, err)
	found := map[string]bool{}
	for _, p := range discovered {
		found[filepath.Base(p)] = true
	}
	for _, f := range files {
		assert.True(t, found[f], f)
	}
}
