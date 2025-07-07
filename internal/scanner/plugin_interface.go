package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"reflect"
	"sync"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// LanguageAnalyzer defines the interface that all language analyzers must implement
type LanguageAnalyzer interface {
	// GetName returns the unique name/identifier for this analyzer
	GetName() string

	// GetSupportedExtensions returns file extensions this analyzer can handle
	GetSupportedExtensions() []string

	// GetSupportedFiles returns specific filenames this analyzer can handle
	GetSupportedFiles() []string

	// ExtractPackages extracts package information from a project
	ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error)

	// AnalyzeDependencies performs dependency analysis and returns a dependency tree
	AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error)

	// ValidateProject checks if the project structure is valid for this analyzer
	ValidateProject(projectInfo *ProjectInfo) error

	// GetMetadata returns metadata about this analyzer
	GetMetadata() *AnalyzerMetadata
}

// AnalyzerMetadata contains information about an analyzer
type AnalyzerMetadata struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Author       string   `json:"author"`
	Languages    []string `json:"languages"`
	Capabilities []string `json:"capabilities"`
	Requirements []string `json:"requirements"`
}

// PluginAnalyzer represents an analyzer loaded from a plugin
type PluginAnalyzer struct {
	plugin   *plugin.Plugin
	analyzer LanguageAnalyzer
	metadata *AnalyzerMetadata
}

// AnalyzerRegistry manages all registered language analyzers
type AnalyzerRegistry struct {
	mu        sync.RWMutex
	analyzers map[string]LanguageAnalyzer
	plugins   map[string]*PluginAnalyzer
	config    *config.Config
}

// NewAnalyzerRegistry creates a new analyzer registry
func NewAnalyzerRegistry(cfg *config.Config) *AnalyzerRegistry {
	return &AnalyzerRegistry{
		analyzers: make(map[string]LanguageAnalyzer),
		plugins:   make(map[string]*PluginAnalyzer),
		config:    cfg,
	}
}

// RegisterAnalyzer registers a built-in analyzer
func (r *AnalyzerRegistry) RegisterAnalyzer(analyzer LanguageAnalyzer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := analyzer.GetName()
	if _, exists := r.analyzers[name]; exists {
		return fmt.Errorf("analyzer %s is already registered", name)
	}

	r.analyzers[name] = analyzer
	return nil
}

// LoadPlugin loads an analyzer from a plugin file
func (r *AnalyzerRegistry) LoadPlugin(pluginPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", pluginPath, err)
	}

	// Look for the NewAnalyzer function
	newAnalyzerSymbol, err := p.Lookup("NewAnalyzer")
	if err != nil {
		return fmt.Errorf("plugin %s does not export NewAnalyzer function: %w", pluginPath, err)
	}

	// Verify the function signature
	newAnalyzerFunc, ok := newAnalyzerSymbol.(func(*config.Config) LanguageAnalyzer)
	if !ok {
		return fmt.Errorf("plugin %s NewAnalyzer function has incorrect signature", pluginPath)
	}

	// Create the analyzer instance
	analyzer := newAnalyzerFunc(r.config)
	if analyzer == nil {
		return fmt.Errorf("plugin %s NewAnalyzer returned nil", pluginPath)
	}

	name := analyzer.GetName()
	if _, exists := r.analyzers[name]; exists {
		return fmt.Errorf("analyzer %s from plugin conflicts with existing analyzer", name)
	}

	pluginAnalyzer := &PluginAnalyzer{
		plugin:   p,
		analyzer: analyzer,
		metadata: analyzer.GetMetadata(),
	}

	r.analyzers[name] = analyzer
	r.plugins[name] = pluginAnalyzer

	return nil
}

// GetAnalyzer retrieves an analyzer by name
func (r *AnalyzerRegistry) GetAnalyzer(name string) (LanguageAnalyzer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	analyzer, exists := r.analyzers[name]
	return analyzer, exists
}

// GetAnalyzerForProject finds the best analyzer for a given project
func (r *AnalyzerRegistry) GetAnalyzerForProject(projectInfo *ProjectInfo) (LanguageAnalyzer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Try to find analyzer based on project files
	for _, analyzer := range r.analyzers {
		// Check supported files
		for _, supportedFile := range analyzer.GetSupportedFiles() {
			filePath := filepath.Join(projectInfo.Path, supportedFile)
			if _, err := os.Stat(filePath); err == nil {
				if err := analyzer.ValidateProject(projectInfo); err == nil {
					return analyzer, nil
				}
			}
		}

		// Check supported extensions
		for _, ext := range analyzer.GetSupportedExtensions() {
			if r.hasFilesWithExtension(projectInfo.Path, ext) {
				if err := analyzer.ValidateProject(projectInfo); err == nil {
					return analyzer, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no suitable analyzer found for project at %s", projectInfo.Path)
}

// GetAllAnalyzers returns all registered analyzers
func (r *AnalyzerRegistry) GetAllAnalyzers() map[string]LanguageAnalyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]LanguageAnalyzer)
	for name, analyzer := range r.analyzers {
		result[name] = analyzer
	}
	return result
}

// GetPluginAnalyzers returns all plugin-based analyzers
func (r *AnalyzerRegistry) GetPluginAnalyzers() map[string]*PluginAnalyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*PluginAnalyzer)
	for name, plugin := range r.plugins {
		result[name] = plugin
	}
	return result
}

// UnloadPlugin unloads a plugin analyzer
func (r *AnalyzerRegistry) UnloadPlugin(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pluginAnalyzer, exists := r.plugins[name]
	if !exists {
		return fmt.Errorf("plugin analyzer %s not found", name)
	}

	delete(r.analyzers, name)
	delete(r.plugins, name)

	// Note: Go plugins cannot be unloaded, but we remove our references
	_ = pluginAnalyzer

	return nil
}

// ValidateAnalyzer checks if an analyzer implements the interface correctly
func (r *AnalyzerRegistry) ValidateAnalyzer(analyzer LanguageAnalyzer) error {
	// Check if analyzer implements all required methods
	analyzerType := reflect.TypeOf(analyzer)
	interfaceType := reflect.TypeOf((*LanguageAnalyzer)(nil)).Elem()

	if !analyzerType.Implements(interfaceType) {
		return fmt.Errorf("analyzer does not implement LanguageAnalyzer interface")
	}

	// Validate metadata
	metadata := analyzer.GetMetadata()
	if metadata == nil {
		return fmt.Errorf("analyzer metadata cannot be nil")
	}

	if metadata.Name == "" {
		return fmt.Errorf("analyzer name cannot be empty")
	}

	if len(metadata.Languages) == 0 {
		return fmt.Errorf("analyzer must support at least one language")
	}

	return nil
}

// hasFilesWithExtension checks if directory contains files with given extension
func (r *AnalyzerRegistry) hasFilesWithExtension(dir, ext string) bool {
	matches, err := filepath.Glob(filepath.Join(dir, "*"+ext))
	return err == nil && len(matches) > 0
}

// AnalyzerContext provides context for analyzer operations
type AnalyzerContext struct {
	Context context.Context
	Config  *config.Config
	Logger  Logger
}

// Logger interface for analyzer logging
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// BaseAnalyzer provides common functionality for analyzers
type BaseAnalyzer struct {
	name           string
	extensions     []string
	supportedFiles []string
	metadata       *AnalyzerMetadata
	config         *config.Config
}

// NewBaseAnalyzer creates a new base analyzer
func NewBaseAnalyzer(name string, extensions, supportedFiles []string, metadata *AnalyzerMetadata, config *config.Config) *BaseAnalyzer {
	return &BaseAnalyzer{
		name:           name,
		extensions:     extensions,
		supportedFiles: supportedFiles,
		metadata:       metadata,
		config:         config,
	}
}

// GetName returns the analyzer name
func (b *BaseAnalyzer) GetName() string {
	return b.name
}

// GetSupportedExtensions returns supported file extensions
func (b *BaseAnalyzer) GetSupportedExtensions() []string {
	return b.extensions
}

// GetSupportedFiles returns supported filenames
func (b *BaseAnalyzer) GetSupportedFiles() []string {
	return b.supportedFiles
}

// GetMetadata returns analyzer metadata
func (b *BaseAnalyzer) GetMetadata() *AnalyzerMetadata {
	return b.metadata
}

// ValidateProject provides basic project validation
func (b *BaseAnalyzer) ValidateProject(projectInfo *ProjectInfo) error {
	if projectInfo == nil {
		return fmt.Errorf("project info cannot be nil")
	}

	if projectInfo.Path == "" {
		return fmt.Errorf("project path cannot be empty")
	}

	if _, err := os.Stat(projectInfo.Path); os.IsNotExist(err) {
		return fmt.Errorf("project path does not exist: %s", projectInfo.Path)
	}

	return nil
}
