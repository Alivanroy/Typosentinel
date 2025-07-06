package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Logger interface for plugin logging
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// PluginManager manages CI/CD platform plugins
type PluginManager struct {
	config          *config.Config
	plugins         map[string]Plugin
	registeredTypes map[string]PluginFactory
	mu              sync.RWMutex
	logger          Logger
	pluginDir       string
	autoDiscover    bool
}

// Plugin represents a CI/CD integration plugin
type Plugin interface {
	// GetInfo returns plugin metadata
	GetInfo() PluginInfo
	
	// Initialize sets up the plugin
	Initialize(ctx context.Context, config map[string]interface{}) error
	
	// Execute runs the plugin with scan results
	Execute(ctx context.Context, results *types.ScanResult) (*PluginResult, error)
	
	// Validate checks if the plugin can run in the current environment
	Validate(ctx context.Context) error
	
	// Cleanup performs plugin cleanup
	Cleanup(ctx context.Context) error
	
	// GetStatus returns current plugin status
	GetStatus() PluginStatus
}

// PluginFactory creates plugin instances
type PluginFactory func(config map[string]interface{}) (Plugin, error)

// PluginInfo contains plugin metadata
type PluginInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Platform     string            `json:"platform"` // github-actions, gitlab-ci, jenkins, etc.
	Capabilities []string          `json:"capabilities"`
	Requirements map[string]string `json:"requirements"`
	ConfigSchema map[string]interface{} `json:"config_schema"`
}

// PluginResult represents the result of plugin execution
type PluginResult struct {
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	Actions     []PluginAction         `json:"actions"`
	Metrics     map[string]interface{} `json:"metrics"`
	Duration    time.Duration          `json:"duration"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Error       error                  `json:"error,omitempty"`
}

// PluginAction represents an action taken by the plugin
type PluginAction struct {
	Type        string                 `json:"type"` // "block", "warn", "notify", "report"
	Target      string                 `json:"target"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
}

// PluginStatus represents plugin status
type PluginStatus struct {
	State       string    `json:"state"` // "active", "inactive", "error", "disabled"
	LastRun     time.Time `json:"last_run"`
	RunCount    int       `json:"run_count"`
	ErrorCount  int       `json:"error_count"`
	LastError   string    `json:"last_error,omitempty"`
	HealthCheck bool      `json:"health_check"`
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Enabled  bool                   `json:"enabled"`
	Platform string                 `json:"platform"`
	Settings map[string]interface{} `json:"settings"`
	Timeout  time.Duration          `json:"timeout"`
	Retries  int                    `json:"retries"`
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(config *config.Config, logger Logger) *PluginManager {
	pluginDir := "./plugins"
	if config.Plugins != nil && config.Plugins.PluginDirectory != "" {
		pluginDir = config.Plugins.PluginDirectory
	}

	return &PluginManager{
		config:          config,
		plugins:         make(map[string]Plugin),
		registeredTypes: make(map[string]PluginFactory),
		logger:          logger,
		pluginDir:       pluginDir,
		autoDiscover:    config.Plugins != nil && config.Plugins.AutoLoad,
	}
}

// Initialize sets up the plugin manager
func (pm *PluginManager) Initialize(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.logger.Info("Initializing plugin manager", map[string]interface{}{"plugin_dir": pm.pluginDir})

	// Register built-in plugin types
	pm.registerBuiltinPlugins()

	// Auto-discover plugins if enabled
	if pm.autoDiscover {
		if err := pm.discoverPlugins(ctx); err != nil {
			pm.logger.Warn("Plugin discovery failed", map[string]interface{}{"error": err})
		}
	}

	// Load configured plugins
	if err := pm.loadConfiguredPlugins(ctx); err != nil {
		return fmt.Errorf("failed to load configured plugins: %w", err)
	}

	pm.logger.Info("Plugin manager initialized", map[string]interface{}{"loaded_plugins": len(pm.plugins)})
	return nil
}

// RegisterPlugin registers a new plugin type
func (pm *PluginManager) RegisterPlugin(platform string, factory PluginFactory) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.registeredTypes[platform]; exists {
		return fmt.Errorf("plugin type %s already registered", platform)
	}

	pm.registeredTypes[platform] = factory
	pm.logger.Debug("Plugin type registered", map[string]interface{}{"platform": platform})
	return nil
}

// LoadPlugin loads and initializes a specific plugin
func (pm *PluginManager) LoadPlugin(ctx context.Context, name, platform string, config map[string]interface{}) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	factory, exists := pm.registeredTypes[platform]
	if !exists {
		return fmt.Errorf("unknown plugin platform: %s", platform)
	}

	plugin, err := factory(config)
	if err != nil {
		return fmt.Errorf("failed to create plugin %s: %w", name, err)
	}

	if err := plugin.Initialize(ctx, config); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
	}

	if err := plugin.Validate(ctx); err != nil {
		return fmt.Errorf("plugin validation failed for %s: %w", name, err)
	}

	pm.plugins[name] = plugin
	pm.logger.Info("Plugin loaded successfully", map[string]interface{}{"name": name, "platform": platform})
	return nil
}

// ExecutePlugins executes all active plugins with scan results
func (pm *PluginManager) ExecutePlugins(ctx context.Context, results *types.ScanResult) ([]PluginResult, error) {
	pm.mu.RLock()
	plugins := make(map[string]Plugin)
	for name, plugin := range pm.plugins {
		plugins[name] = plugin
	}
	pm.mu.RUnlock()

	var pluginResults []PluginResult
	var wg sync.WaitGroup
	resultsChan := make(chan PluginResult, len(plugins))

	// Execute plugins concurrently
	for name, plugin := range plugins {
		wg.Add(1)
		go func(pluginName string, p Plugin) {
			defer wg.Done()
			
			start := time.Now()
			result, err := p.Execute(ctx, results)
			if err != nil {
				result = &PluginResult{
					Success:  false,
					Message:  fmt.Sprintf("Plugin execution failed: %v", err),
					Error:    err,
					Duration: time.Since(start),
				}
				pm.logger.Error("Plugin execution failed", map[string]interface{}{"plugin": pluginName, "error": err})
			} else {
				result.Duration = time.Since(start)
				pm.logger.Debug("Plugin executed successfully", map[string]interface{}{"plugin": pluginName, "duration": result.Duration})
			}
			
			resultsChan <- *result
		}(name, plugin)
	}

	// Wait for all plugins to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		pluginResults = append(pluginResults, result)
	}

	pm.logger.Info("Plugin execution completed", map[string]interface{}{"total_plugins": len(plugins), "results": len(pluginResults)})
	return pluginResults, nil
}

// GetPlugin returns a specific plugin by name
func (pm *PluginManager) GetPlugin(name string) (Plugin, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	plugin, exists := pm.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", name)
	}

	return plugin, nil
}

// ListPlugins returns information about all loaded plugins
func (pm *PluginManager) ListPlugins() map[string]PluginInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pluginInfos := make(map[string]PluginInfo)
	for name, plugin := range pm.plugins {
		pluginInfos[name] = plugin.GetInfo()
	}

	return pluginInfos
}

// GetPluginStatus returns the status of all plugins
func (pm *PluginManager) GetPluginStatus() map[string]PluginStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	statuses := make(map[string]PluginStatus)
	for name, plugin := range pm.plugins {
		statuses[name] = plugin.GetStatus()
	}

	return statuses
}

// UnloadPlugin unloads a specific plugin
func (pm *PluginManager) UnloadPlugin(ctx context.Context, name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	plugin, exists := pm.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}

	if err := plugin.Cleanup(ctx); err != nil {
		pm.logger.Warn("Plugin cleanup failed", map[string]interface{}{"plugin": name, "error": err})
	}

	delete(pm.plugins, name)
	pm.logger.Info("Plugin unloaded", map[string]interface{}{"name": name})
	return nil
}

// Shutdown gracefully shuts down all plugins
func (pm *PluginManager) Shutdown(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.logger.Info("Shutting down plugin manager", map[string]interface{}{})

	for name, plugin := range pm.plugins {
		if err := plugin.Cleanup(ctx); err != nil {
			pm.logger.Warn("Plugin cleanup failed during shutdown", map[string]interface{}{"plugin": name, "error": err})
		}
	}

	pm.plugins = make(map[string]Plugin)
	pm.logger.Info("Plugin manager shutdown completed", map[string]interface{}{})
	return nil
}

// Helper methods

func (pm *PluginManager) registerBuiltinPlugins() {
	// Register GitHub Actions plugin
	pm.registeredTypes["github-actions"] = func(config map[string]interface{}) (Plugin, error) {
		return NewGitHubActionsPlugin(config, pm.logger), nil
	}

	// Register GitLab CI plugin
	pm.registeredTypes["gitlab-ci"] = func(config map[string]interface{}) (Plugin, error) {
		return NewGitLabCIPlugin(pm.logger), nil
	}

	// Register Jenkins plugin
	pm.registeredTypes["jenkins"] = func(config map[string]interface{}) (Plugin, error) {
		return NewJenkinsPlugin(pm.logger), nil
	}

	// Register Azure DevOps plugin
	pm.registeredTypes["azure-devops"] = func(config map[string]interface{}) (Plugin, error) {
		return NewAzureDevOpsPlugin(pm.logger), nil
	}

	// Register CircleCI plugin
	pm.registeredTypes["circleci"] = func(config map[string]interface{}) (Plugin, error) {
		return NewCircleCIPlugin(pm.logger), nil
	}

	// Register generic webhook plugin
	pm.registeredTypes["webhook"] = func(config map[string]interface{}) (Plugin, error) {
		return NewWebhookPlugin(pm.logger), nil
	}
}

func (pm *PluginManager) discoverPlugins(ctx context.Context) error {
	if _, err := os.Stat(pm.pluginDir); os.IsNotExist(err) {
		pm.logger.Debug("Plugin directory does not exist", map[string]interface{}{"dir": pm.pluginDir})
		return nil
	}

	return filepath.WalkDir(pm.pluginDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		// Try to load plugin configuration
		if err := pm.loadPluginFromFile(ctx, path); err != nil {
			pm.logger.Warn("Failed to load plugin from file", map[string]interface{}{"file": path, "error": err})
		}

		return nil
	})
}

func (pm *PluginManager) loadPluginFromFile(ctx context.Context, configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read plugin config: %w", err)
	}

	var pluginConfig struct {
		Name     string                 `json:"name"`
		Type     string                 `json:"type"`
		Enabled  bool                   `json:"enabled"`
		Settings map[string]interface{} `json:"settings"`
	}

	if err := json.Unmarshal(data, &pluginConfig); err != nil {
		return fmt.Errorf("failed to parse plugin config: %w", err)
	}

	if !pluginConfig.Enabled {
		pm.logger.Debug("Plugin disabled, skipping", map[string]interface{}{"name": pluginConfig.Name})
		return nil
	}

	return pm.LoadPlugin(ctx, pluginConfig.Name, pluginConfig.Type, pluginConfig.Settings)
}

func (pm *PluginManager) loadConfiguredPlugins(ctx context.Context) error {
	// Load plugins from configuration
	if pm.config.Plugins != nil && pm.config.Plugins.CICD != nil {
		for name, pluginConfig := range pm.config.Plugins.CICD {
			if !pluginConfig.Enabled {
				continue
			}

			if err := pm.LoadPlugin(ctx, name, name, pluginConfig.Settings); err != nil {
				pm.logger.Warn("Failed to load configured plugin", map[string]interface{}{"name": name, "error": err})
				continue
			}
		}
	}

	return nil
}