package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"typosentinel/internal/config"
	"typosentinel/internal/scanner"
)

// TestPluginSystemIntegration tests the complete plugin system integration
func TestPluginSystemIntegration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "plugin-integration-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create plugin directory
	pluginDir := filepath.Join(tempDir, "plugins")
	err = os.MkdirAll(pluginDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create plugin directory: %v", err)
	}

	// Create a test configuration
	cfg := &config.Config{
		Plugins: &config.PluginConfig{
			Enabled:         true,
			PluginDirectory: pluginDir,
			AutoLoad:        true,
			LoadTimeout:     30,
			MaxPlugins:      10,
			Validation: config.PluginValidationConfig{
				Enabled:           true,
				CheckSignature:    false,
				RequiredMetadata:  []string{"name", "version"},
				AllowedExtensions: []string{".so"},
			},
			Security: config.PluginSecurityConfig{
				Sandboxed:        false,
				AllowedPaths:     []string{tempDir},
				RestrictedAPIs:   []string{},
				MaxMemoryUsage:   "100MB",
				MaxExecutionTime: 30,
			},
			Plugins: []config.PluginEntry{
				{
					Name:    "test-plugin",
					Path:    filepath.Join(pluginDir, "test-plugin.so"),
					Enabled: true,
					Config: map[string]interface{}{
						"test_setting": "test_value",
						"timeout":      30,
					},
				},
			},
		},
		Scanner: config.ScannerConfig{
			Timeout:        60,
			MaxConcurrency: 4,
			CacheEnabled:   true,
		},
	}

	// Test 1: Initialize Scanner with Plugin System
	t.Run("InitializeScannerWithPlugins", func(t *testing.T) {
		s, err := scanner.New(cfg)
		if err != nil {
			t.Fatalf("Failed to create scanner: %v", err)
		}

		if s == nil {
			t.Fatal("Scanner is nil")
		}

		// Verify that the analyzer registry is initialized
		loadedPlugins := s.GetLoadedPlugins()
		if loadedPlugins == nil {
			t.Error("GetLoadedPlugins returned nil")
		}
	})

	// Test 2: Plugin Manager Integration
	t.Run("PluginManagerIntegration", func(t *testing.T) {
		registry := scanner.NewAnalyzerRegistry(cfg)
		pluginManager := scanner.NewPluginManager(cfg, registry)

		err := pluginManager.Initialize()
		if err != nil {
			t.Fatalf("Failed to initialize plugin manager: %v", err)
		}
		defer pluginManager.Shutdown()

		// Test listing available plugins
		availablePlugins, err := pluginManager.ListAvailablePlugins()
		if err != nil {
			t.Fatalf("Failed to list available plugins: %v", err)
		}

		t.Logf("Available plugins: %v", availablePlugins)

		// Test getting loaded plugins
		loadedPlugins := pluginManager.GetLoadedPlugins()
		if loadedPlugins == nil {
			t.Error("GetLoadedPlugins returned nil")
		}

		t.Logf("Loaded plugins: %d", len(loadedPlugins))
	})

	// Test 3: Plugin Configuration Loading
	t.Run("PluginConfigurationLoading", func(t *testing.T) {
		// Create a test config file
		configFile := filepath.Join(tempDir, "config.yaml")
		configData := `
plugins:
  enabled: true
  plugin_directory: "` + pluginDir + `"
  auto_load: true
  load_timeout: 30
  max_plugins: 10
  validation:
    enabled: true
    check_signature: false
    required_metadata:
      - "name"
      - "version"
    allowed_extensions:
      - ".so"
  security:
    sandboxed: false
    allowed_paths:
      - "` + tempDir + `"
    restricted_apis: []
    max_memory_usage: "100MB"
    max_execution_time: 30
  plugins:
    - name: "test-plugin"
      path: "` + filepath.Join(pluginDir, "test-plugin.so") + `"
      enabled: true
      config:
        test_setting: "test_value"
        timeout: 30
`

		err := os.WriteFile(configFile, []byte(configData), 0644)
		if err != nil {
			t.Fatalf("Failed to write config file: %v", err)
		}

		// Test loading configuration
		loadedCfg, err := config.LoadFromFile(configFile)
		if err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}

		if !loadedCfg.Plugins.Enabled {
			t.Error("Plugins not enabled in loaded config")
		}

		if loadedCfg.Plugins.PluginDirectory != pluginDir {
			t.Errorf("Plugin directory mismatch: expected %s, got %s", pluginDir, loadedCfg.Plugins.PluginDirectory)
		}

		if len(loadedCfg.Plugins.Plugins) != 1 {
			t.Errorf("Expected 1 plugin in config, got %d", len(loadedCfg.Plugins.Plugins))
		}
	})

	// Test 4: Plugin Validation
	t.Run("PluginValidation", func(t *testing.T) {
		registry := scanner.NewAnalyzerRegistry(cfg)
		pluginManager := scanner.NewPluginManager(cfg, registry)

		err := pluginManager.Initialize()
		if err != nil {
			t.Fatalf("Failed to initialize plugin manager: %v", err)
		}
		defer pluginManager.Shutdown()

		// Test validating a non-existent plugin
		err = pluginManager.ValidatePlugin("/tmp/non-existent.so")
		if err == nil {
			t.Error("Expected error when validating non-existent plugin")
		}

		// Create a dummy plugin file for validation testing
		dummyPlugin := filepath.Join(pluginDir, "dummy.so")
		err = os.WriteFile(dummyPlugin, []byte("dummy content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create dummy plugin file: %v", err)
		}

		// This should fail because it's not a valid plugin
		err = pluginManager.ValidatePlugin(dummyPlugin)
		if err == nil {
			t.Error("Expected error when validating invalid plugin")
		}
	})

	// Test 5: Plugin Lifecycle Management
	t.Run("PluginLifecycleManagement", func(t *testing.T) {
		registry := scanner.NewAnalyzerRegistry(cfg)
		pluginManager := scanner.NewPluginManager(cfg, registry)

		err := pluginManager.Initialize()
		if err != nil {
			t.Fatalf("Failed to initialize plugin manager: %v", err)
		}
		defer pluginManager.Shutdown()

		// Test loading a plugin entry
		pluginEntry := config.PluginEntry{
			Name:    "test-lifecycle",
			Path:    "/tmp/test-lifecycle.so",
			Enabled: true,
			Config: map[string]interface{}{
				"test": "value",
			},
		}

		// This should fail because the plugin doesn't exist
		err = pluginManager.LoadPlugin(pluginEntry)
		if err == nil {
			t.Error("Expected error when loading non-existent plugin")
		}

		// Test unloading a non-existent plugin
		err = pluginManager.UnloadPlugin("non-existent")
		if err == nil {
			t.Error("Expected error when unloading non-existent plugin")
		}

		// Test reloading a non-existent plugin
		err = pluginManager.ReloadPlugin("non-existent")
		if err == nil {
			t.Error("Expected error when reloading non-existent plugin")
		}

		// Test enabling/disabling non-existent plugin
		err = pluginManager.EnablePlugin("non-existent")
		if err == nil {
			t.Error("Expected error when enabling non-existent plugin")
		}

		err = pluginManager.DisablePlugin("non-existent")
		if err == nil {
			t.Error("Expected error when disabling non-existent plugin")
		}
	})

	// Test 6: Plugin Information Retrieval
	t.Run("PluginInformationRetrieval", func(t *testing.T) {
		registry := scanner.NewAnalyzerRegistry(cfg)
		pluginManager := scanner.NewPluginManager(cfg, registry)

		err := pluginManager.Initialize()
		if err != nil {
			t.Fatalf("Failed to initialize plugin manager: %v", err)
		}
		defer pluginManager.Shutdown()

		// Test getting plugin info for non-existent plugin
		info, exists := pluginManager.GetPluginInfo("non-existent")
		if exists {
			t.Error("Expected plugin to not exist")
		}
		if info != nil {
			t.Error("Expected nil info for non-existent plugin")
		}

		// Test getting loaded plugins
		loadedPlugins := pluginManager.GetLoadedPlugins()
		if loadedPlugins == nil {
			t.Error("GetLoadedPlugins returned nil")
		}

		// Test listing available plugins
		availablePlugins, err := pluginManager.ListAvailablePlugins()
		if err != nil {
			t.Fatalf("Failed to list available plugins: %v", err)
		}

		t.Logf("Available plugins: %v", availablePlugins)
	})

	// Test 7: Plugin Watcher
	t.Run("PluginWatcher", func(t *testing.T) {
		registry := scanner.NewAnalyzerRegistry(cfg)
		pluginManager := scanner.NewPluginManager(cfg, registry)

		err := pluginManager.Initialize()
		if err != nil {
			t.Fatalf("Failed to initialize plugin manager: %v", err)
		}
		defer pluginManager.Shutdown()

		// Give the watcher a moment to start
		time.Sleep(100 * time.Millisecond)

		// Test that watcher is running (we can't easily test the actual watching without complex setup)
		// Just verify it doesn't crash
		pluginManager.StopWatcher()
	})

	// Test 8: Configuration Serialization
	t.Run("ConfigurationSerialization", func(t *testing.T) {
		// Test JSON serialization of plugin config
		jsonData, err := json.Marshal(cfg.Plugins)
		if err != nil {
			t.Fatalf("Failed to marshal plugin config to JSON: %v", err)
		}

		var deserializedConfig config.PluginConfig
		err = json.Unmarshal(jsonData, &deserializedConfig)
		if err != nil {
			t.Fatalf("Failed to unmarshal plugin config from JSON: %v", err)
		}

		if deserializedConfig.Enabled != cfg.Plugins.Enabled {
			t.Error("Plugin enabled setting not preserved during serialization")
		}

		if deserializedConfig.PluginDirectory != cfg.Plugins.PluginDirectory {
			t.Error("Plugin directory not preserved during serialization")
		}
	})

	// Test 9: Error Handling
	t.Run("ErrorHandling", func(t *testing.T) {
		// Test with invalid plugin directory
		invalidCfg := *cfg
		invalidCfg.Plugins.PluginDirectory = "/invalid/path/that/does/not/exist"

		registry := scanner.NewAnalyzerRegistry(&invalidCfg)
		pluginManager := scanner.NewPluginManager(&invalidCfg, registry)

		err := pluginManager.Initialize()
		if err != nil {
			t.Fatalf("Failed to initialize plugin manager: %v", err)
		}
		defer pluginManager.Shutdown()

		// This should handle the invalid directory gracefully
		availablePlugins, err := pluginManager.ListAvailablePlugins()
		if err != nil {
			t.Fatalf("Failed to list available plugins with invalid directory: %v", err)
		}

		if len(availablePlugins) != 0 {
			t.Errorf("Expected 0 plugins with invalid directory, got %d", len(availablePlugins))
		}
	})

	// Test 10: Concurrent Access
	t.Run("ConcurrentAccess", func(t *testing.T) {
		registry := scanner.NewAnalyzerRegistry(cfg)
		pluginManager := scanner.NewPluginManager(cfg, registry)

		err := pluginManager.Initialize()
		if err != nil {
			t.Fatalf("Failed to initialize plugin manager: %v", err)
		}
		defer pluginManager.Shutdown()

		// Test concurrent access to plugin manager methods
		done := make(chan bool, 10)

		// Start multiple goroutines accessing plugin manager concurrently
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- true }()

				// Test various operations concurrently
				_ = pluginManager.GetLoadedPlugins()
				_, _ = pluginManager.ListAvailablePlugins()
				_, _ = pluginManager.GetPluginInfo("test")
				_ = pluginManager.ValidatePlugin("/tmp/test.so")
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			select {
			case <-done:
				// Success
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for concurrent operations to complete")
			}
		}
	})
}

// TestPluginSystemPerformance tests the performance characteristics of the plugin system
func TestPluginSystemPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "plugin-performance-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create plugin directory
	pluginDir := filepath.Join(tempDir, "plugins")
	err = os.MkdirAll(pluginDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create plugin directory: %v", err)
	}

	// Create multiple dummy plugin files
	for i := 0; i < 100; i++ {
		pluginFile := filepath.Join(pluginDir, fmt.Sprintf("plugin%d.so", i))
		err = os.WriteFile(pluginFile, []byte("dummy content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create dummy plugin file: %v", err)
		}
	}

	cfg := &config.Config{
		Plugins: &config.PluginConfig{
			Enabled:         true,
			PluginDirectory: pluginDir,
			AutoLoad:        false,
			LoadTimeout:     30,
			MaxPlugins:      100,
			Validation: config.PluginValidationConfig{
				Enabled:           true,
				CheckSignature:    false,
				RequiredMetadata:  []string{"name", "version"},
				AllowedExtensions: []string{".so"},
			},
			Security: config.PluginSecurityConfig{
				Sandboxed:        false,
				AllowedPaths:     []string{tempDir},
				RestrictedAPIs:   []string{},
				MaxMemoryUsage:   "100MB",
				MaxExecutionTime: 30,
			},
			Plugins: []config.PluginEntry{},
		},
	}

	registry := scanner.NewAnalyzerRegistry(cfg)
	pluginManager := scanner.NewPluginManager(cfg, registry)

	err = pluginManager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize plugin manager: %v", err)
	}
	defer pluginManager.Shutdown()

	// Benchmark listing available plugins
	start := time.Now()
	availablePlugins, err := pluginManager.ListAvailablePlugins()
	if err != nil {
		t.Fatalf("Failed to list available plugins: %v", err)
	}
	duration := time.Since(start)

	t.Logf("Listed %d plugins in %v", len(availablePlugins), duration)

	if duration > 1*time.Second {
		t.Errorf("Listing plugins took too long: %v", duration)
	}

	if len(availablePlugins) != 100 {
		t.Errorf("Expected 100 plugins, got %d", len(availablePlugins))
	}
}