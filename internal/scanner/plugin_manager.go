package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"sync"
	"time"

	"typosentinel/internal/config"
)

// PluginManager manages the plugin lifecycle and provides advanced plugin management
type PluginManager struct {
	config           *config.Config
	analyzerRegistry *AnalyzerRegistry
	loadedPlugins    map[string]*PluginInfo
	mu               sync.RWMutex
	watcher          *PluginWatcher
}

// PluginInfo contains information about a loaded plugin
type PluginInfo struct {
	Name        string                 `json:"name"`
	Path        string                 `json:"path"`
	Version     string                 `json:"version"`
	Author      string                 `json:"author"`
	Description string                 `json:"description"`
	LoadedAt    time.Time              `json:"loaded_at"`
	Enabled     bool                   `json:"enabled"`
	Config      map[string]interface{} `json:"config"`
	Analyzer    LanguageAnalyzer       `json:"-"`
}

// PluginWatcher watches for plugin file changes
type PluginWatcher struct {
	manager *PluginManager
	stopCh  chan struct{}
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(cfg *config.Config, registry *AnalyzerRegistry) *PluginManager {
	return &PluginManager{
		config:           cfg,
		analyzerRegistry: registry,
		loadedPlugins:    make(map[string]*PluginInfo),
	}
}

// Initialize initializes the plugin manager
func (pm *PluginManager) Initialize() error {
	if pm.config.Plugins == nil || !pm.config.Plugins.Enabled {
		return nil
	}

	// Create plugin directory if it doesn't exist
	if pm.config.Plugins.PluginDirectory != "" {
		if err := os.MkdirAll(pm.config.Plugins.PluginDirectory, 0755); err != nil {
			return fmt.Errorf("failed to create plugin directory: %w", err)
		}
	}

	// Load plugins
	if err := pm.LoadAllPlugins(); err != nil {
		return fmt.Errorf("failed to load plugins: %w", err)
	}

	// Start plugin watcher if auto-reload is enabled
	if pm.config.Plugins.AutoLoad {
		pm.startWatcher()
	}

	return nil
}

// LoadAllPlugins loads all configured plugins
func (pm *PluginManager) LoadAllPlugins() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var errors []error

	// Load plugins from directory
	if pm.config.Plugins.AutoLoad && pm.config.Plugins.PluginDirectory != "" {
		if err := pm.loadPluginsFromDirectory(); err != nil {
			errors = append(errors, err)
		}
	}

	// Load specific plugins from configuration
	for _, pluginEntry := range pm.config.Plugins.Plugins {
		if pluginEntry.Enabled {
			if err := pm.loadPlugin(pluginEntry); err != nil {
				errors = append(errors, fmt.Errorf("failed to load plugin %s: %w", pluginEntry.Name, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("plugin loading errors: %v", errors)
	}

	return nil
}

// loadPluginsFromDirectory loads plugins from the plugin directory
func (pm *PluginManager) loadPluginsFromDirectory() error {
	if _, err := os.Stat(pm.config.Plugins.PluginDirectory); os.IsNotExist(err) {
		return nil
	}

	return filepath.Walk(pm.config.Plugins.PluginDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}

		// Only load .so files (Go plugins)
		if filepath.Ext(path) == ".so" {
			pluginEntry := config.PluginEntry{
				Name:    filepath.Base(path),
				Path:    path,
				Enabled: true,
			}
			pm.loadPlugin(pluginEntry)
		}

		return nil
	})
}

// LoadPlugin loads a single plugin from a plugin entry
func (pm *PluginManager) LoadPlugin(pluginEntry config.PluginEntry) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.loadPlugin(pluginEntry)
}

// loadPlugin loads a single plugin from a plugin entry (internal)
func (pm *PluginManager) loadPlugin(pluginEntry config.PluginEntry) error {
	// Check if plugin is already loaded
	if _, exists := pm.loadedPlugins[pluginEntry.Name]; exists {
		return fmt.Errorf("plugin %s is already loaded", pluginEntry.Name)
	}

	// Load plugin through analyzer registry
	if err := pm.analyzerRegistry.LoadPlugin(pluginEntry.Path); err != nil {
		return err
	}

	// Get the loaded analyzer
	analyzer, exists := pm.analyzerRegistry.GetAnalyzer(pluginEntry.Name)
	if !exists {
		return fmt.Errorf("plugin %s was loaded but analyzer not found", pluginEntry.Name)
	}

	// Create plugin info
	pluginInfo := &PluginInfo{
		Name:        pluginEntry.Name,
		Path:        pluginEntry.Path,
		LoadedAt:    time.Now(),
		Enabled:     true,
		Config:      pluginEntry.Config,
		Analyzer:    analyzer,
	}

	// Extract metadata if available
	if metadata := analyzer.GetMetadata(); metadata != nil {
		pluginInfo.Version = metadata.Version
		pluginInfo.Author = metadata.Author
		pluginInfo.Description = metadata.Description
	}

	pm.loadedPlugins[pluginEntry.Name] = pluginInfo
	return nil
}

// UnloadPlugin unloads a plugin
func (pm *PluginManager) UnloadPlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	_, exists := pm.loadedPlugins[name]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", name)
	}

	// Unload from analyzer registry
	if err := pm.analyzerRegistry.UnloadPlugin(name); err != nil {
		return err
	}

	// Remove from loaded plugins
	delete(pm.loadedPlugins, name)

	return nil
}

// ReloadPlugin reloads a plugin
func (pm *PluginManager) ReloadPlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pluginInfo, exists := pm.loadedPlugins[name]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", name)
	}

	// Unload plugin
	if err := pm.analyzerRegistry.UnloadPlugin(name); err != nil {
		return err
	}

	// Reload plugin
	pluginEntry := config.PluginEntry{
		Name:    pluginInfo.Name,
		Path:    pluginInfo.Path,
		Enabled: true,
		Config:  pluginInfo.Config,
	}

	return pm.loadPlugin(pluginEntry)
}

// GetLoadedPlugins returns information about all loaded plugins
func (pm *PluginManager) GetLoadedPlugins() map[string]*PluginInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[string]*PluginInfo)
	for name, info := range pm.loadedPlugins {
		result[name] = info
	}
	return result
}

// ListAvailablePlugins returns a list of available plugin files in the plugin directory
func (pm *PluginManager) ListAvailablePlugins() ([]string, error) {
	pluginDir := pm.config.Plugins.PluginDirectory
	if pluginDir == "" {
		return nil, fmt.Errorf("plugin directory not configured")
	}

	files, err := filepath.Glob(filepath.Join(pluginDir, "*.so"))
	if err != nil {
		return nil, fmt.Errorf("failed to list plugin files: %w", err)
	}

	var plugins []string
	for _, file := range files {
		plugins = append(plugins, filepath.Base(file))
	}

	return plugins, nil
}

// GetPluginInfo returns information about a specific plugin
func (pm *PluginManager) GetPluginInfo(name string) (*PluginInfo, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	info, exists := pm.loadedPlugins[name]
	return info, exists
}

// ValidatePlugin validates a plugin file without loading it
func (pm *PluginManager) ValidatePlugin(pluginPath string) error {
	// Check if file exists
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin file does not exist: %s", pluginPath)
	}
	
	// Check file extension
	if !strings.HasSuffix(pluginPath, ".so") {
		return fmt.Errorf("invalid plugin file extension: %s", pluginPath)
	}
	
	// Try to open the plugin to validate it
	plugin, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}
	
	// Check for required symbols
	_, err = plugin.Lookup("GetAnalyzer")
	if err != nil {
		return fmt.Errorf("plugin missing required GetAnalyzer function: %w", err)
	}
	
	return nil
}

// EnablePlugin enables a plugin
func (pm *PluginManager) EnablePlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pluginInfo, exists := pm.loadedPlugins[name]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", name)
	}

	pluginInfo.Enabled = true
	return nil
}

// DisablePlugin disables a plugin
func (pm *PluginManager) DisablePlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pluginInfo, exists := pm.loadedPlugins[name]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", name)
	}

	pluginInfo.Enabled = false
	return nil
}

// startWatcher starts the plugin file watcher
func (pm *PluginManager) startWatcher() {
	pm.watcher = &PluginWatcher{
		manager: pm,
		stopCh:  make(chan struct{}),
	}

	// Start watching in a goroutine
	go pm.watcher.watch()
}

// StopWatcher stops the plugin file watcher
func (pm *PluginManager) StopWatcher() {
	if pm.watcher != nil {
		close(pm.watcher.stopCh)
		pm.watcher = nil
	}
}

// watch watches for plugin file changes
func (pw *PluginWatcher) watch() {
	// This is a simplified watcher implementation
	// In a production environment, you might want to use fsnotify
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check for new plugins or changes
			pw.checkForChanges()
		case <-pw.stopCh:
			return
		}
	}
}

// checkForChanges checks for plugin file changes
func (pw *PluginWatcher) checkForChanges() {
	// Implementation for detecting plugin changes
	// This could include checking file modification times,
	// detecting new plugin files, etc.
}

// Shutdown gracefully shuts down the plugin manager
func (pm *PluginManager) Shutdown() error {
	pm.StopWatcher()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Unload all plugins
	for name := range pm.loadedPlugins {
		pm.analyzerRegistry.UnloadPlugin(name)
	}

	pm.loadedPlugins = make(map[string]*PluginInfo)
	return nil
}