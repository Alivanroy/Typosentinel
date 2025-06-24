package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
)

func TestPluginManager_Initialize(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	if pm.config != cfg {
		t.Error("Config not set correctly")
	}

	if pm.analyzerRegistry != registry {
		t.Error("Registry not set correctly")
	}

	if pm.loadedPlugins == nil {
		t.Error("Plugins map not initialized")
	}
}

func TestPluginManager_LoadPlugin(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins: []config.PluginEntry{}, // Empty plugins list to avoid loading during init
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	// Test loading a non-existent plugin (should fail gracefully)
	entry := config.PluginEntry{
		Name:    "non-existent",
		Path:    "/tmp/non-existent.so",
		Enabled: true,
	}

	err = pm.LoadPlugin(entry)
	if err == nil {
		t.Error("Expected error when loading non-existent plugin")
	}
}

func TestPluginManager_UnloadPlugin(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	// Test unloading a non-existent plugin
	err = pm.UnloadPlugin("non-existent")
	if err == nil {
		t.Error("Expected error when unloading non-existent plugin")
	}
}

func TestPluginManager_ReloadPlugin(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	// Test reloading a non-existent plugin
	err = pm.ReloadPlugin("non-existent")
	if err == nil {
		t.Error("Expected error when reloading non-existent plugin")
	}
}

func TestPluginManager_EnableDisablePlugin(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	// Test enabling a non-existent plugin
	err = pm.EnablePlugin("non-existent")
	if err == nil {
		t.Error("Expected error when enabling non-existent plugin")
	}

	// Test disabling a non-existent plugin
	err = pm.DisablePlugin("non-existent")
	if err == nil {
		t.Error("Expected error when disabling non-existent plugin")
	}
}

func TestPluginManager_GetLoadedPlugins(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	loadedPlugins := pm.GetLoadedPlugins()
	if loadedPlugins == nil {
		t.Error("GetLoadedPlugins returned nil")
	}

	if len(loadedPlugins) != 0 {
		t.Errorf("Expected 0 loaded plugins, got %d", len(loadedPlugins))
	}
}

func TestPluginManager_ListAvailablePlugins(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "plugin-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create some test plugin files
	testPlugins := []string{"plugin1.so", "plugin2.so", "not-a-plugin.txt"}
	for _, plugin := range testPlugins {
		file, err := os.Create(filepath.Join(tempDir, plugin))
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", plugin, err)
		}
		file.Close()
	}

	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: tempDir,
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err = pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	availablePlugins, err := pm.ListAvailablePlugins()
	if err != nil {
		t.Fatalf("Failed to list available plugins: %v", err)
	}

	// Should only find .so files
	expectedCount := 2
	if len(availablePlugins) != expectedCount {
		t.Errorf("Expected %d available plugins, got %d", expectedCount, len(availablePlugins))
	}

	// Check that only .so files are included
	for _, plugin := range availablePlugins {
		if filepath.Ext(plugin) != ".so" {
			t.Errorf("Non-.so file found in available plugins: %s", plugin)
		}
	}
}

func TestPluginManager_GetPluginInfo(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	// Test getting info for non-existent plugin
	info, exists := pm.GetPluginInfo("non-existent")
	if exists {
		t.Error("Expected plugin to not exist")
	}
	if info != nil {
		t.Error("Expected nil info for non-existent plugin")
	}
}

func TestPluginManager_ValidatePlugin(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	// Test validating a non-existent plugin
	err = pm.ValidatePlugin("/tmp/non-existent.so")
	if err == nil {
		t.Error("Expected error when validating non-existent plugin")
	}
}

func TestPluginWatcher(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        true,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	defer pm.Shutdown()

	// Test that watcher is created
	if pm.watcher == nil {
		t.Error("Plugin watcher not created")
	}

	// Test stopping watcher
	pm.StopWatcher()
	if pm.watcher != nil {
		t.Error("Plugin watcher not stopped")
	}
}

func TestPluginManager_Shutdown(t *testing.T) {
	cfg := &config.Config{
		Plugins: &config.PluginsConfig{
			Enabled:         true,
			PluginDirectory: "/tmp/test-plugins",
			AutoLoad:        false,
			Plugins:         []config.PluginEntry{},
		},
	}

	registry := NewAnalyzerRegistry(cfg)
	pm := NewPluginManager(cfg, registry)

	err := pm.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}

	// Add a mock plugin to test cleanup
	pm.loadedPlugins["test-plugin"] = &PluginInfo{
		Name:     "test-plugin",
		Path:     "/tmp/test-plugin.so",
		Version:  "1.0.0",
		Author:   "Test Author",
		LoadedAt: time.Now(),
		Enabled:  true,
		Config:   map[string]interface{}{"test": "value"},
	}

	err = pm.Shutdown()
	if err != nil {
		t.Fatalf("Failed to shutdown plugin manager: %v", err)
	}

	// Verify cleanup
	if len(pm.loadedPlugins) != 0 {
		t.Error("Plugins not cleaned up after shutdown")
	}

	if pm.watcher != nil {
		t.Error("Watcher not stopped after shutdown")
	}
}