package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/spf13/cobra"
)

// pluginCmd represents the plugin command
var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage TypoSentinel plugins",
	Long: `Manage TypoSentinel plugins for language analysis.

Plugins extend TypoSentinel's capabilities by adding support for new
programming languages and package managers. Use this command to list,
load, unload, and manage plugins.`,
}

// pluginListCmd lists all available and loaded plugins
var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available and loaded plugins",
	Long:  `List all available plugins in the plugin directory and show their status.`,
	RunE:  runPluginList,
}

// pluginLoadCmd loads a plugin
var pluginLoadCmd = &cobra.Command{
	Use:   "load <plugin-path>",
	Short: "Load a plugin",
	Long:  `Load a plugin from the specified path.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginLoad,
}

// pluginUnloadCmd unloads a plugin
var pluginUnloadCmd = &cobra.Command{
	Use:   "unload <plugin-name>",
	Short: "Unload a plugin",
	Long:  `Unload a previously loaded plugin by name.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginUnload,
}

// pluginInfoCmd shows detailed information about a plugin
var pluginInfoCmd = &cobra.Command{
	Use:   "info <plugin-name>",
	Short: "Show plugin information",
	Long:  `Show detailed information about a specific plugin.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginInfo,
}

// pluginValidateCmd validates a plugin
var pluginValidateCmd = &cobra.Command{
	Use:   "validate <plugin-path>",
	Short: "Validate a plugin",
	Long:  `Validate a plugin file before loading it.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginValidate,
}

// pluginReloadCmd reloads a plugin
var pluginReloadCmd = &cobra.Command{
	Use:   "reload <plugin-name>",
	Short: "Reload a plugin",
	Long:  `Reload a plugin to pick up changes.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginReload,
}

var (
	pluginOutputFormat string
	pluginShowAll      bool
)

func init() {
	rootCmd.AddCommand(pluginCmd)
	pluginCmd.AddCommand(pluginListCmd)
	pluginCmd.AddCommand(pluginLoadCmd)
	pluginCmd.AddCommand(pluginUnloadCmd)
	pluginCmd.AddCommand(pluginInfoCmd)
	pluginCmd.AddCommand(pluginValidateCmd)
	pluginCmd.AddCommand(pluginReloadCmd)

	// Flags for plugin list command
	pluginListCmd.Flags().StringVarP(&pluginOutputFormat, "output", "o", "table", "Output format (table, json, yaml)")
	pluginListCmd.Flags().BoolVarP(&pluginShowAll, "all", "a", false, "Show all plugins including disabled ones")
}

func runPluginList(cmd *cobra.Command, args []string) error {
	cfg := config.NewDefaultConfig()

	// Create plugin manager
	registry := scanner.NewAnalyzerRegistry(cfg)
	pluginManager := scanner.NewPluginManager(cfg, registry)

	if err := pluginManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}
	defer pluginManager.Shutdown()

	// Get loaded plugins
	loadedPlugins := pluginManager.GetLoadedPlugins()

	// Get available plugins
	availablePlugins, err := pluginManager.ListAvailablePlugins()
	if err != nil {
		return fmt.Errorf("failed to list available plugins: %w", err)
	}

	// Create plugin status list
	type PluginStatus struct {
		Name        string    `json:"name"`
		Path        string    `json:"path,omitempty"`
		Version     string    `json:"version,omitempty"`
		Author      string    `json:"author,omitempty"`
		Description string    `json:"description,omitempty"`
		Status      string    `json:"status"`
		LoadedAt    time.Time `json:"loaded_at,omitempty"`
		Enabled     bool      `json:"enabled"`
	}

	var plugins []PluginStatus

	// Add loaded plugins
	for name, info := range loadedPlugins {
		plugins = append(plugins, PluginStatus{
			Name:        name,
			Path:        info.Path,
			Version:     info.Version,
			Author:      info.Author,
			Description: info.Description,
			Status:      "loaded",
			LoadedAt:    info.LoadedAt,
			Enabled:     info.Enabled,
		})
	}

	// Add available but not loaded plugins
	for _, availablePlugin := range availablePlugins {
		loaded := false
		for name := range loadedPlugins {
			if strings.Contains(availablePlugin, name) {
				loaded = true
				break
			}
		}
		if !loaded {
			plugins = append(plugins, PluginStatus{
				Name:    strings.TrimSuffix(availablePlugin, ".so"),
				Status:  "available",
				Enabled: false,
			})
		}
	}

	// Filter plugins if not showing all
	if !pluginShowAll {
		var filteredPlugins []PluginStatus
		for _, plugin := range plugins {
			if plugin.Status == "loaded" || plugin.Enabled {
				filteredPlugins = append(filteredPlugins, plugin)
			}
		}
		plugins = filteredPlugins
	}

	// Sort plugins by name
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Name < plugins[j].Name
	})

	// Output in requested format
	switch pluginOutputFormat {
	case "json":
		return outputJSON(plugins)
	case "yaml":
		return outputYAML(plugins)
	default:
		// Convert to []interface{} for outputPluginTable
		var pluginInterfaces []interface{}
		for _, plugin := range plugins {
			pluginInterfaces = append(pluginInterfaces, plugin)
		}
		return outputPluginTable(pluginInterfaces)
	}
}

func runPluginLoad(cmd *cobra.Command, args []string) error {
	pluginPath := args[0]

	cfg := config.NewDefaultConfig()

	// Create plugin manager
	registry := scanner.NewAnalyzerRegistry(cfg)
	pluginManager := scanner.NewPluginManager(cfg, registry)

	if err := pluginManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}
	defer pluginManager.Shutdown()

	// Validate plugin first
	if err := pluginManager.ValidatePlugin(pluginPath); err != nil {
		return fmt.Errorf("plugin validation failed: %w", err)
	}

	// Load plugin
	pluginEntry := config.PluginEntry{
		Name:    filepath.Base(pluginPath),
		Path:    pluginPath,
		Enabled: true,
	}

	if err := registry.LoadPlugin(pluginPath); err != nil {
		return fmt.Errorf("failed to load plugin: %w", err)
	}

	fmt.Printf("Plugin loaded successfully: %s\n", pluginEntry.Name)
	return nil
}

func runPluginUnload(cmd *cobra.Command, args []string) error {
	pluginName := args[0]

	cfg := config.NewDefaultConfig()

	// Create plugin manager
	registry := scanner.NewAnalyzerRegistry(cfg)
	pluginManager := scanner.NewPluginManager(cfg, registry)

	if err := pluginManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}
	defer pluginManager.Shutdown()

	// Unload plugin
	if err := pluginManager.UnloadPlugin(pluginName); err != nil {
		return fmt.Errorf("failed to unload plugin: %w", err)
	}

	fmt.Printf("Plugin unloaded successfully: %s\n", pluginName)
	return nil
}

func runPluginInfo(cmd *cobra.Command, args []string) error {
	pluginName := args[0]

	cfg := config.NewDefaultConfig()

	// Create plugin manager
	registry := scanner.NewAnalyzerRegistry(cfg)
	pluginManager := scanner.NewPluginManager(cfg, registry)

	if err := pluginManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}
	defer pluginManager.Shutdown()

	// Get plugin info
	pluginInfo, exists := pluginManager.GetPluginInfo(pluginName)
	if !exists {
		return fmt.Errorf("plugin not found: %s", pluginName)
	}

	// Display plugin information
	fmt.Printf("Plugin Information\n")
	fmt.Printf("==================\n")
	fmt.Printf("Name:        %s\n", pluginInfo.Name)
	fmt.Printf("Version:     %s\n", pluginInfo.Version)
	fmt.Printf("Author:      %s\n", pluginInfo.Author)
	fmt.Printf("Description: %s\n", pluginInfo.Description)
	fmt.Printf("Path:        %s\n", pluginInfo.Path)
	fmt.Printf("Loaded At:   %s\n", pluginInfo.LoadedAt.Format(time.RFC3339))
	fmt.Printf("Enabled:     %t\n", pluginInfo.Enabled)

	if pluginInfo.Analyzer != nil {
		metadata := pluginInfo.Analyzer.GetMetadata()
		if metadata != nil {
			fmt.Printf("\nAnalyzer Metadata\n")
			fmt.Printf("=================\n")
			fmt.Printf("Languages:     %v\n", metadata.Languages)
			fmt.Printf("Capabilities:  %v\n", metadata.Capabilities)
			fmt.Printf("Requirements:  %v\n", metadata.Requirements)
		}
	}

	if len(pluginInfo.Config) > 0 {
		fmt.Printf("\nConfiguration\n")
		fmt.Printf("=============\n")
		for key, value := range pluginInfo.Config {
			fmt.Printf("%s: %v\n", key, value)
		}
	}

	return nil
}

func runPluginValidate(cmd *cobra.Command, args []string) error {
	pluginPath := args[0]

	cfg := config.NewDefaultConfig()

	// Create plugin manager
	registry := scanner.NewAnalyzerRegistry(cfg)
	pluginManager := scanner.NewPluginManager(cfg, registry)

	// Validate plugin
	if err := pluginManager.ValidatePlugin(pluginPath); err != nil {
		return fmt.Errorf("plugin validation failed: %w", err)
	}

	fmt.Printf("Plugin validation successful: %s\n", pluginPath)
	return nil
}

func runPluginReload(cmd *cobra.Command, args []string) error {
	pluginName := args[0]

	cfg := config.NewDefaultConfig()

	// Create plugin manager
	registry := scanner.NewAnalyzerRegistry(cfg)
	pluginManager := scanner.NewPluginManager(cfg, registry)

	if err := pluginManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize plugin manager: %w", err)
	}
	defer pluginManager.Shutdown()

	// Reload plugin
	if err := pluginManager.ReloadPlugin(pluginName); err != nil {
		return fmt.Errorf("failed to reload plugin: %w", err)
	}

	fmt.Printf("Plugin reloaded successfully: %s\n", pluginName)
	return nil
}

func outputPluginTable(plugins []interface{}) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATUS\tVERSION\tAUTHOR\tDESCRIPTION")
	fmt.Fprintln(w, "----\t------\t-------\t------\t-----------")

	for _, p := range plugins {
		if plugin, ok := p.(struct {
			Name        string    `json:"name"`
			Path        string    `json:"path,omitempty"`
			Version     string    `json:"version,omitempty"`
			Author      string    `json:"author,omitempty"`
			Description string    `json:"description,omitempty"`
			Status      string    `json:"status"`
			LoadedAt    time.Time `json:"loaded_at,omitempty"`
			Enabled     bool      `json:"enabled"`
		}); ok {
			description := plugin.Description
			if len(description) > 50 {
				description = description[:47] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				plugin.Name,
				plugin.Status,
				plugin.Version,
				plugin.Author,
				description)
		}
	}

	return w.Flush()
}

func outputJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func outputYAML(data interface{}) error {
	// For simplicity, we'll output JSON format
	// In a real implementation, you'd use a YAML library
	return outputJSON(data)
}
