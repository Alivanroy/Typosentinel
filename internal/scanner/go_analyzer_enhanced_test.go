package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
)

func TestEnhancedGoAnalyzer_ParseGoMod(t *testing.T) {
	tests := []struct {
		name     string
		goMod    string
		expected *GoModuleInfo
	}{
		{
			name: "Basic go.mod",
			goMod: `module example.com/myproject

go 1.19

require (
	github.com/gorilla/mux v1.8.0
	github.com/lib/pq v1.10.7
	golang.org/x/crypto v0.5.0 // indirect
)

replace github.com/old/module => github.com/new/module v1.0.0

exclude github.com/bad/module v1.0.0

retract v1.0.1 // security issue
`,
			expected: &GoModuleInfo{
				Module:    "example.com/myproject",
				GoVersion: "1.19",
				Requires: []GoRequirement{
					{Path: "github.com/gorilla/mux", Version: "v1.8.0", Indirect: false},
					{Path: "github.com/lib/pq", Version: "v1.10.7", Indirect: false},
					{Path: "golang.org/x/crypto", Version: "v0.5.0", Indirect: true},
				},
				Replaces: []GoReplace{
					{OldPath: "github.com/old/module", NewPath: "github.com/new/module", NewVersion: "v1.0.0"},
				},
				Excludes: []GoExclude{
					{Path: "github.com/bad/module", Version: "v1.0.0"},
				},
				Retracts: []GoRetract{
					{Version: "v1.0.1", Reason: "security issue"},
				},
			},
		},
		{
			name: "Single line requires",
			goMod: `module example.com/simple

go 1.20

require github.com/single/dep v1.0.0
require github.com/another/dep v2.0.0 // indirect
`,
			expected: &GoModuleInfo{
				Module:    "example.com/simple",
				GoVersion: "1.20",
				Requires: []GoRequirement{
					{Path: "github.com/single/dep", Version: "v1.0.0", Indirect: false},
					{Path: "github.com/another/dep", Version: "v2.0.0", Indirect: true},
				},
				Replaces: []GoReplace{},
				Excludes: []GoExclude{},
				Retracts: []GoRetract{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory and go.mod file
			tmpDir := t.TempDir()
			goModPath := filepath.Join(tmpDir, "go.mod")
			err := os.WriteFile(goModPath, []byte(tt.goMod), 0644)
			if err != nil {
				t.Fatalf("Failed to write go.mod: %v", err)
			}

			analyzer := NewEnhancedGoAnalyzer(&config.Config{})
			result, err := analyzer.parseGoMod(tmpDir)
			if err != nil {
				t.Fatalf("parseGoMod failed: %v", err)
			}

			// Verify module and go version
			if result.Module != tt.expected.Module {
				t.Errorf("Expected module %s, got %s", tt.expected.Module, result.Module)
			}
			if result.GoVersion != tt.expected.GoVersion {
				t.Errorf("Expected go version %s, got %s", tt.expected.GoVersion, result.GoVersion)
			}

			// Verify requires
			if len(result.Requires) != len(tt.expected.Requires) {
				t.Errorf("Expected %d requires, got %d", len(tt.expected.Requires), len(result.Requires))
			} else {
				for i, req := range result.Requires {
					expected := tt.expected.Requires[i]
					if req.Path != expected.Path || req.Version != expected.Version || req.Indirect != expected.Indirect {
						t.Errorf("Require %d: expected %+v, got %+v", i, expected, req)
					}
				}
			}

			// Verify replaces
			if len(result.Replaces) != len(tt.expected.Replaces) {
				t.Errorf("Expected %d replaces, got %d", len(tt.expected.Replaces), len(result.Replaces))
			}

			// Verify excludes
			if len(result.Excludes) != len(tt.expected.Excludes) {
				t.Errorf("Expected %d excludes, got %d", len(tt.expected.Excludes), len(result.Excludes))
			}

			// Verify retracts
			if len(result.Retracts) != len(tt.expected.Retracts) {
				t.Errorf("Expected %d retracts, got %d", len(tt.expected.Retracts), len(result.Retracts))
			}
		})
	}
}

func TestEnhancedGoAnalyzer_ParseGoSum(t *testing.T) {
	goSum := `github.com/gorilla/mux v1.8.0 h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=
github.com/gorilla/mux v1.8.0/go.mod h1:DVbg23sWSpFRCP0SfiEN6jmj59UnW/n46BH5rLB71So=
github.com/lib/pq v1.10.7 h1:p7ZhMD+KsSRozJr34udlUrhboJwWAgCg34+/ZZNvZZw=
github.com/lib/pq v1.10.7/go.mod h1:AlVN5x4E4T544tWzH6hKfbfQvm3HdbOxrmggDNAPY9o=
`

	// Create temporary directory and go.sum file
	tmpDir := t.TempDir()
	goSumPath := filepath.Join(tmpDir, "go.sum")
	err := os.WriteFile(goSumPath, []byte(goSum), 0644)
	if err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	analyzer := NewEnhancedGoAnalyzer(&config.Config{})
	entries, err := analyzer.parseGoSum(tmpDir)
	if err != nil {
		t.Fatalf("parseGoSum failed: %v", err)
	}

	// Verify entries
	expectedEntries := map[string]string{
		"github.com/gorilla/mux v1.8.0":     "h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=",
		"github.com/gorilla/mux v1.8.0/go.mod": "h1:DVbg23sWSpFRCP0SfiEN6jmj59UnW/n46BH5rLB71So=",
		"github.com/lib/pq v1.10.7":         "h1:p7ZhMD+KsSRozJr34udlUrhboJwWAgCg34+/ZZNvZZw=",
		"github.com/lib/pq v1.10.7/go.mod":     "h1:AlVN5x4E4T544tWzH6hKfbfQvm3HdbOxrmggDNAPY9o=",
	}

	for key, expectedChecksum := range expectedEntries {
		if entry, exists := entries[key]; !exists {
			t.Errorf("Expected entry %s not found", key)
		} else if entry.Checksum != expectedChecksum {
			t.Errorf("Expected checksum %s for %s, got %s", expectedChecksum, key, entry.Checksum)
		}
	}
}

func TestEnhancedGoAnalyzer_ExtractPackages(t *testing.T) {
	goMod := `module example.com/testproject

go 1.19

require (
	github.com/gorilla/mux v1.8.0
	github.com/lib/pq v1.10.7
	golang.org/x/crypto v0.5.0 // indirect
	github.com/stretchr/testify v1.8.1 // test dependency
)
`

	goSum := `github.com/gorilla/mux v1.8.0 h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=
github.com/lib/pq v1.10.7 h1:p7ZhMD+KsSRozJr34udlUrhboJwWAgCg34+/ZZNvZZw=
golang.org/x/crypto v0.5.0 h1:U/0M97KRkSFvyD/3FSmdP5W5swImpNgle/EHFhOsQPE=
github.com/stretchr/testify v1.8.1 h1:w7B6lhMri9wdJUVmEZPGGhZzrYTPvgJArz7wNPgYKsk=
`

	// Create temporary directory with go.mod and go.sum
	tmpDir := t.TempDir()
	goModPath := filepath.Join(tmpDir, "go.mod")
	goSumPath := filepath.Join(tmpDir, "go.sum")
	
	err := os.WriteFile(goModPath, []byte(goMod), 0644)
	if err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}
	
	err = os.WriteFile(goSumPath, []byte(goSum), 0644)
	if err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	projectInfo := &ProjectInfo{
		Path: tmpDir,
		Metadata: map[string]string{
			"module": "example.com/testproject",
		},
	}

	config := &config.Config{}
	// Network requests are disabled by default in enhanced analyzer
	analyzer := NewEnhancedGoAnalyzer(config)
	packages, err := analyzer.ExtractPackages(projectInfo)
	if err != nil {
		t.Fatalf("ExtractPackages failed: %v", err)
	}

	// Verify packages
	expectedPackages := map[string]struct {
		version  string
		pkgType  string
		indirect bool
	}{
		"github.com/gorilla/mux":     {version: "v1.8.0", pkgType: "production", indirect: false},
		"github.com/lib/pq":          {version: "v1.10.7", pkgType: "production", indirect: false},
		"golang.org/x/crypto":        {version: "v0.5.0", pkgType: "indirect", indirect: true},
		"github.com/stretchr/testify": {version: "v1.8.1", pkgType: "test", indirect: false},
	}

	if len(packages) != len(expectedPackages) {
		t.Errorf("Expected %d packages, got %d", len(expectedPackages), len(packages))
	}

	for _, pkg := range packages {
		expected, exists := expectedPackages[pkg.Name]
		if !exists {
			t.Errorf("Unexpected package: %s", pkg.Name)
			continue
		}

		if pkg.Version != expected.version {
			t.Errorf("Package %s: expected version %s, got %s", pkg.Name, expected.version, pkg.Version)
		}

		if pkg.Type != expected.pkgType {
			t.Errorf("Package %s: expected type %s, got %s", pkg.Name, expected.pkgType, pkg.Type)
		}

		if pkg.Registry != "go" {
			t.Errorf("Package %s: expected registry 'go', got %s", pkg.Name, pkg.Registry)
		}

		// Check metadata for checksum
		if pkg.Metadata != nil && pkg.Metadata.Metadata != nil {
			if checksum, exists := pkg.Metadata.Metadata["checksum"]; exists {
				if checksum == "" {
					t.Errorf("Package %s: checksum should not be empty", pkg.Name)
				}
			}
			if indirect, exists := pkg.Metadata.Metadata["indirect"]; exists {
				if indirect != expected.indirect {
					t.Errorf("Package %s: expected indirect %v, got %v", pkg.Name, expected.indirect, indirect)
				}
			}
		}
	}
}

func TestEnhancedGoAnalyzer_DeterminePackageType(t *testing.T) {
	tests := []struct {
		name     string
		req      GoRequirement
		expected string
	}{
		{
			name:     "Indirect dependency",
			req:      GoRequirement{Path: "github.com/some/dep", Version: "v1.0.0", Indirect: true},
			expected: "indirect",
		},
		{
			name:     "Test dependency - testify",
			req:      GoRequirement{Path: "github.com/stretchr/testify", Version: "v1.8.1", Indirect: false},
			expected: "test",
		},
		{
			name:     "Test dependency - assert",
			req:      GoRequirement{Path: "github.com/go-playground/assert", Version: "v2.0.1", Indirect: false},
			expected: "test",
		},
		{
			name:     "Test dependency - mock",
			req:      GoRequirement{Path: "github.com/golang/mock", Version: "v1.6.0", Indirect: false},
			expected: "test",
		},
		{
			name:     "Production dependency",
			req:      GoRequirement{Path: "github.com/gorilla/mux", Version: "v1.8.0", Indirect: false},
			expected: "production",
		},
	}

	analyzer := NewEnhancedGoAnalyzer(&config.Config{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.determinePackageType(tt.req)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestEnhancedGoAnalyzer_AnalyzeDependencies(t *testing.T) {
	goMod := `module example.com/testproject

go 1.19

require (
	github.com/gorilla/mux v1.8.0
	github.com/lib/pq v1.10.7
)
`

	// Create temporary directory with go.mod
	tmpDir := t.TempDir()
	goModPath := filepath.Join(tmpDir, "go.mod")
	
	err := os.WriteFile(goModPath, []byte(goMod), 0644)
	if err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	projectInfo := &ProjectInfo{
		Path: tmpDir,
		Metadata: map[string]string{
			"module": "example.com/testproject",
		},
	}

	analyzer := NewEnhancedGoAnalyzer(&config.Config{})
	tree, err := analyzer.AnalyzeDependencies(projectInfo)
	if err != nil {
		t.Fatalf("AnalyzeDependencies failed: %v", err)
	}

	// Verify root
	if tree.Name != "example.com/testproject" {
		t.Errorf("Expected root name 'example.com/testproject', got %s", tree.Name)
	}
	if tree.Type != "root" {
		t.Errorf("Expected root type 'root', got %s", tree.Type)
	}

	// Verify dependencies
	if len(tree.Dependencies) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(tree.Dependencies))
	}

	expectedDeps := map[string]string{
		"github.com/gorilla/mux": "v1.8.0",
		"github.com/lib/pq":      "v1.10.7",
	}

	for _, dep := range tree.Dependencies {
		depName, ok := dep.Name.(string)
		if !ok {
			t.Errorf("Dependency name is not a string: %v", dep.Name)
			continue
		}
		depVersion, ok := dep.Version.(string)
		if !ok {
			t.Errorf("Dependency version is not a string: %v", dep.Version)
			continue
		}
		expectedVersion, exists := expectedDeps[depName]
		if !exists {
			t.Errorf("Unexpected dependency: %s", depName)
			continue
		}
		if depVersion != expectedVersion {
			t.Errorf("Dependency %s: expected version %s, got %s", depName, expectedVersion, depVersion)
		}
	}
}

func TestEnhancedGoAnalyzer_ParseRequireLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *GoRequirement
	}{
		{
			name:     "Direct dependency",
			line:     "github.com/gorilla/mux v1.8.0",
			expected: &GoRequirement{Path: "github.com/gorilla/mux", Version: "v1.8.0", Indirect: false},
		},
		{
			name:     "Indirect dependency",
			line:     "golang.org/x/crypto v0.5.0 // indirect",
			expected: &GoRequirement{Path: "golang.org/x/crypto", Version: "v0.5.0", Indirect: true},
		},
		{
			name:     "Require prefix",
			line:     "require github.com/lib/pq v1.10.7",
			expected: &GoRequirement{Path: "github.com/lib/pq", Version: "v1.10.7", Indirect: false},
		},
		{
			name:     "Invalid line",
			line:     "invalid",
			expected: nil,
		},
	}

	analyzer := NewEnhancedGoAnalyzer(&config.Config{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseRequireLine(tt.line)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %+v", result)
				}
			} else {
				if result == nil {
					t.Errorf("Expected %+v, got nil", tt.expected)
				} else if *result != *tt.expected {
					t.Errorf("Expected %+v, got %+v", tt.expected, result)
				}
			}
		})
	}
}

func TestEnhancedGoAnalyzer_ParseReplaceLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected *GoReplace
	}{
		{
			name:     "Basic replace",
			line:     "github.com/old/module => github.com/new/module v1.0.0",
			expected: &GoReplace{OldPath: "github.com/old/module", NewPath: "github.com/new/module", NewVersion: "v1.0.0"},
		},
		{
			name:     "Replace with version",
			line:     "github.com/old/module v1.0.0 => github.com/new/module v2.0.0",
			expected: &GoReplace{OldPath: "github.com/old/module", OldVersion: "v1.0.0", NewPath: "github.com/new/module", NewVersion: "v2.0.0"},
		},
		{
			name:     "Replace prefix",
			line:     "replace github.com/old/module => github.com/new/module v1.0.0",
			expected: &GoReplace{OldPath: "github.com/old/module", NewPath: "github.com/new/module", NewVersion: "v1.0.0"},
		},
		{
			name:     "Invalid line",
			line:     "invalid",
			expected: nil,
		},
	}

	analyzer := NewEnhancedGoAnalyzer(&config.Config{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseReplaceLine(tt.line)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %+v", result)
				}
			} else {
				if result == nil {
					t.Errorf("Expected %+v, got nil", tt.expected)
				} else if *result != *tt.expected {
					t.Errorf("Expected %+v, got %+v", tt.expected, result)
				}
			}
		})
	}
}

func TestNewEnhancedGoAnalyzer(t *testing.T) {
	// Test with default GOPROXY
	analyzer := NewEnhancedGoAnalyzer(&config.Config{})
	if analyzer.proxyURL != "https://proxy.golang.org" {
		t.Errorf("Expected default proxy URL 'https://proxy.golang.org', got %s", analyzer.proxyURL)
	}

	// Test with custom GOPROXY
	os.Setenv("GOPROXY", "https://custom.proxy.com")
	defer os.Unsetenv("GOPROXY")
	
	analyzer2 := NewEnhancedGoAnalyzer(&config.Config{})
	if analyzer2.proxyURL != "https://custom.proxy.com" {
		t.Errorf("Expected custom proxy URL 'https://custom.proxy.com', got %s", analyzer2.proxyURL)
	}

	// Verify HTTP client timeout
	if analyzer.httpClient.Timeout != 30*time.Second {
		t.Errorf("Expected HTTP client timeout 30s, got %v", analyzer.httpClient.Timeout)
	}
}