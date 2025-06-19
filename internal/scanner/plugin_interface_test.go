package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

// MockAnalyzer implements LanguageAnalyzer for testing
type MockAnalyzer struct {
	*BaseAnalyzer
	name string
}

func NewMockAnalyzer(name string, cfg *config.Config) *MockAnalyzer {
	metadata := &AnalyzerMetadata{
		Name:        name,
		Version:     "1.0.0",
		Description: "Mock analyzer for testing",
		Author:      "Test",
		Languages:   []string{"mock"},
		Capabilities: []string{"testing"},
		Requirements: []string{"test.txt"},
	}
	
	baseAnalyzer := NewBaseAnalyzer(
		name,
		[]string{".mock"},
		[]string{"test.txt"},
		metadata,
		cfg,
	)
	
	return &MockAnalyzer{
		BaseAnalyzer: baseAnalyzer,
		name:         name,
	}
}

func (m *MockAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	return []*types.Package{
		{
			Name:     "mock-package",
			Version:  "1.0.0",
			Registry: "mock-registry",
			Type:     "production",
		},
	}, nil
}

func (m *MockAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	return &types.DependencyTree{
		Name:         "mock-project",
		Version:      "1.0.0",
		Type:         "mock",
		Dependencies: []types.DependencyTree{},
		CreatedAt:    time.Now(),
	}, nil
}

func TestAnalyzerRegistry_RegisterAnalyzer(t *testing.T) {
	cfg := &config.Config{}
	registry := NewAnalyzerRegistry(cfg)
	
	mockAnalyzer := NewMockAnalyzer("test-analyzer", cfg)
	
	err := registry.RegisterAnalyzer(mockAnalyzer)
	if err != nil {
		t.Fatalf("Failed to register analyzer: %v", err)
	}
	
	// Test duplicate registration
	err = registry.RegisterAnalyzer(mockAnalyzer)
	if err == nil {
		t.Fatal("Expected error for duplicate analyzer registration")
	}
	
	// Test retrieval
	retrieved, exists := registry.GetAnalyzer("test-analyzer")
	if !exists {
		t.Fatal("Analyzer not found after registration")
	}
	
	if retrieved.GetName() != "test-analyzer" {
		t.Fatalf("Expected analyzer name 'test-analyzer', got '%s'", retrieved.GetName())
	}
}

func TestAnalyzerRegistry_GetAnalyzerForProject(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := os.MkdirTemp("", "test-project")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	cfg := &config.Config{}
	registry := NewAnalyzerRegistry(cfg)
	
	mockAnalyzer := NewMockAnalyzer("test-analyzer", cfg)
	err = registry.RegisterAnalyzer(mockAnalyzer)
	if err != nil {
		t.Fatalf("Failed to register analyzer: %v", err)
	}
	
	projectInfo := &ProjectInfo{
		Path:         tempDir,
		Type:         "mock",
		ManifestFile: "test.txt",
	}
	
	analyzer, err := registry.GetAnalyzerForProject(projectInfo)
	if err != nil {
		t.Fatalf("Failed to get analyzer for project: %v", err)
	}
	
	if analyzer.GetName() != "test-analyzer" {
		t.Fatalf("Expected analyzer name 'test-analyzer', got '%s'", analyzer.GetName())
	}
}

func TestAnalyzerRegistry_ValidateAnalyzer(t *testing.T) {
	cfg := &config.Config{}
	registry := NewAnalyzerRegistry(cfg)
	
	mockAnalyzer := NewMockAnalyzer("test-analyzer", cfg)
	
	err := registry.ValidateAnalyzer(mockAnalyzer)
	if err != nil {
		t.Fatalf("Analyzer validation failed: %v", err)
	}
}

func TestBaseAnalyzer(t *testing.T) {
	cfg := &config.Config{}
	metadata := &AnalyzerMetadata{
		Name:        "base-test",
		Version:     "1.0.0",
		Description: "Base analyzer test",
		Author:      "Test",
		Languages:   []string{"test"},
		Capabilities: []string{"testing"},
		Requirements: []string{"test.txt"},
	}
	
	baseAnalyzer := NewBaseAnalyzer(
		"base-test",
		[]string{".test"},
		[]string{"test.txt"},
		metadata,
		cfg,
	)
	
	if baseAnalyzer.GetName() != "base-test" {
		t.Fatalf("Expected name 'base-test', got '%s'", baseAnalyzer.GetName())
	}
	
	extensions := baseAnalyzer.GetSupportedExtensions()
	if len(extensions) != 1 || extensions[0] != ".test" {
		t.Fatalf("Expected extensions ['.test'], got %v", extensions)
	}
	
	files := baseAnalyzer.GetSupportedFiles()
	if len(files) != 1 || files[0] != "test.txt" {
		t.Fatalf("Expected files ['test.txt'], got %v", files)
	}
	
	retrievedMetadata := baseAnalyzer.GetMetadata()
	if retrievedMetadata.Name != "base-test" {
		t.Fatalf("Expected metadata name 'base-test', got '%s'", retrievedMetadata.Name)
	}
}

func TestBaseAnalyzer_ValidateProject(t *testing.T) {
	cfg := &config.Config{}
	metadata := &AnalyzerMetadata{
		Name:        "validation-test",
		Version:     "1.0.0",
		Description: "Validation test",
		Author:      "Test",
		Languages:   []string{"test"},
		Capabilities: []string{"testing"},
		Requirements: []string{"test.txt"},
	}
	
	baseAnalyzer := NewBaseAnalyzer(
		"validation-test",
		[]string{".test"},
		[]string{"test.txt"},
		metadata,
		cfg,
	)
	
	// Test nil project info
	err := baseAnalyzer.ValidateProject(nil)
	if err == nil {
		t.Fatal("Expected error for nil project info")
	}
	
	// Test empty path
	err = baseAnalyzer.ValidateProject(&ProjectInfo{Path: ""})
	if err == nil {
		t.Fatal("Expected error for empty project path")
	}
	
	// Test non-existent path
	err = baseAnalyzer.ValidateProject(&ProjectInfo{Path: "/non/existent/path"})
	if err == nil {
		t.Fatal("Expected error for non-existent project path")
	}
	
	// Test valid path
	tempDir, err := os.MkdirTemp("", "validation-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	err = baseAnalyzer.ValidateProject(&ProjectInfo{Path: tempDir})
	if err != nil {
		t.Fatalf("Validation failed for valid project: %v", err)
	}
}

func TestAnalyzerRegistry_GetAllAnalyzers(t *testing.T) {
	cfg := &config.Config{}
	registry := NewAnalyzerRegistry(cfg)
	
	mockAnalyzer1 := NewMockAnalyzer("analyzer1", cfg)
	mockAnalyzer2 := NewMockAnalyzer("analyzer2", cfg)
	
	registry.RegisterAnalyzer(mockAnalyzer1)
	registry.RegisterAnalyzer(mockAnalyzer2)
	
	allAnalyzers := registry.GetAllAnalyzers()
	
	if len(allAnalyzers) != 2 {
		t.Fatalf("Expected 2 analyzers, got %d", len(allAnalyzers))
	}
	
	if _, exists := allAnalyzers["analyzer1"]; !exists {
		t.Fatal("analyzer1 not found in all analyzers")
	}
	
	if _, exists := allAnalyzers["analyzer2"]; !exists {
		t.Fatal("analyzer2 not found in all analyzers")
	}
}

func BenchmarkAnalyzerRegistry_GetAnalyzer(b *testing.B) {
	cfg := &config.Config{}
	registry := NewAnalyzerRegistry(cfg)
	
	mockAnalyzer := NewMockAnalyzer("benchmark-analyzer", cfg)
	registry.RegisterAnalyzer(mockAnalyzer)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.GetAnalyzer("benchmark-analyzer")
	}
}

func BenchmarkAnalyzerRegistry_RegisterAnalyzer(b *testing.B) {
	cfg := &config.Config{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		registry := NewAnalyzerRegistry(cfg)
		mockAnalyzer := NewMockAnalyzer("benchmark-analyzer", cfg)
		b.StartTimer()
		
		_ = registry.RegisterAnalyzer(mockAnalyzer)
	}
}