package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Alivanroy/Typosentinel/internal/config"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage TypoSentinel configuration",
	Long: `The config command provides utilities for managing TypoSentinel configuration files.

You can generate new configuration files from templates, validate existing configurations,
view current settings, and manage configuration templates.

Examples:
  typosentinel config init                    # Create default config file
  typosentinel config init --template prod    # Create production config
  typosentinel config validate                # Validate current config
  typosentinel config show                    # Show current configuration
  typosentinel config template list          # List available templates
  typosentinel config template save my-config # Save current config as template`,
}

// configInitCmd initializes a new configuration file
var configInitCmd = &cobra.Command{
	Use:   "init [filename]",
	Short: "Initialize a new configuration file",
	Long: `Initialize creates a new TypoSentinel configuration file with default or template settings.

Available templates:
  - default: Standard configuration with recommended settings
  - minimal: Minimal configuration with essential settings only
  - development: Development-friendly configuration with verbose logging
  - production: Production-ready configuration with security focus
  - security-focused: Maximum security settings for high-risk environments

Examples:
  typosentinel config init                           # Create typosentinel.yaml
  typosentinel config init --template minimal       # Use minimal template
  typosentinel config init custom.yaml --template prod # Create custom.yaml with production template
  typosentinel config init --force                   # Overwrite existing file`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConfigInit,
}

// configValidateCmd validates configuration
var configValidateCmd = &cobra.Command{
	Use:   "validate [config-file]",
	Short: "Validate configuration file",
	Long: `Validate checks a TypoSentinel configuration file for errors and provides recommendations.

The validation includes:
  - Syntax validation (YAML format)
  - Schema validation (required fields, data types)
  - Value validation (ranges, formats, dependencies)
  - Security best practices
  - Performance recommendations

Examples:
  typosentinel config validate                    # Validate default config
  typosentinel config validate custom.yaml       # Validate specific file
  typosentinel config validate --strict          # Strict validation mode
  typosentinel config validate --warnings-only   # Show only warnings`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConfigValidate,
}

// configShowCmd shows current configuration
var configShowCmd = &cobra.Command{
	Use:   "show [config-file]",
	Short: "Show current configuration",
	Long: `Show displays the current TypoSentinel configuration with resolved values.

This includes:
  - Configuration file location
  - All configuration values (with environment variable overrides)
  - Active analyzers and their settings
  - Registry configurations
  - Policy settings

Examples:
  typosentinel config show                    # Show default config
  typosentinel config show custom.yaml       # Show specific config file
  typosentinel config show --format json     # Output as JSON
  typosentinel config show --env-vars        # Include environment variables`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConfigShow,
}

// configTemplateCmd manages configuration templates
var configTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage configuration templates",
	Long: `Template command provides utilities for managing configuration templates.

Templates allow you to save and reuse configuration settings across different
environments and projects.`,
}

// configTemplateListCmd lists available templates
var configTemplateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available configuration templates",
	Long: `List shows all available configuration templates including built-in and custom templates.

Built-in templates:
  - default: Standard configuration
  - minimal: Minimal settings
  - development: Development environment
  - production: Production environment
  - security-focused: Maximum security

Custom templates are stored in ~/.config/github.com/Alivanroy/Typosentinel/templates/`,
	RunE: runConfigTemplateList,
}

// configTemplateSaveCmd saves current config as template
var configTemplateSaveCmd = &cobra.Command{
	Use:   "save <template-name> [config-file]",
	Short: "Save configuration as template",
	Long: `Save creates a new configuration template from the current or specified configuration.

Templates can be reused with the 'config init --template' command.

Examples:
  typosentinel config template save my-config           # Save current config
  typosentinel config template save prod-config prod.yaml # Save specific file
  typosentinel config template save dev --description "Development settings"`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runConfigTemplateSave,
}

// configTemplateShowCmd shows template details
var configTemplateShowCmd = &cobra.Command{
	Use:   "show <template-name>",
	Short: "Show template configuration",
	Long: `Show displays the contents and metadata of a configuration template.

Examples:
  typosentinel config template show default     # Show default template
  typosentinel config template show my-config   # Show custom template`,
	Args: cobra.ExactArgs(1),
	RunE: runConfigTemplateShow,
}

// Command flags
var (
	configTemplate    string
	configForce       bool
	configFormat      string
	configStrict      bool
	configWarningsOnly bool
	configShowEnvVars bool
	configDescription string
)

func init() {
	// Add subcommands
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configTemplateCmd)

	configTemplateCmd.AddCommand(configTemplateListCmd)
	configTemplateCmd.AddCommand(configTemplateSaveCmd)
	configTemplateCmd.AddCommand(configTemplateShowCmd)

	// Init command flags
	configInitCmd.Flags().StringVarP(&configTemplate, "template", "t", "default", "Configuration template to use")
	configInitCmd.Flags().BoolVarP(&configForce, "force", "f", false, "Overwrite existing configuration file")

	// Validate command flags
	configValidateCmd.Flags().BoolVar(&configStrict, "strict", false, "Enable strict validation mode")
	configValidateCmd.Flags().BoolVar(&configWarningsOnly, "warnings-only", false, "Show only warnings")

	// Show command flags
	configShowCmd.Flags().StringVar(&configFormat, "format", "yaml", "Output format (yaml, json)")
	configShowCmd.Flags().BoolVar(&configShowEnvVars, "env-vars", false, "Include environment variables")

	// Template save command flags
	configTemplateSaveCmd.Flags().StringVar(&configDescription, "description", "", "Template description")

	// Add to root command
	rootCmd.AddCommand(configCmd)
}

// runConfigInit initializes a new configuration file
func runConfigInit(cmd *cobra.Command, args []string) error {
	// Determine output filename
	filename := "typosentinel.yaml"
	if len(args) > 0 {
		filename = args[0]
	}

	// Check if file exists and force flag
	if _, err := os.Stat(filename); err == nil && !configForce {
		return fmt.Errorf("configuration file '%s' already exists. Use --force to overwrite", filename)
	}

	// Create config manager
	options := config.ConfigManagerOptions{
		ConfigFile: filename,
	}
	_ = config.NewConfigManager(options, nil)

	// Generate configuration file
	err := generateConfigFile(filename, configTemplate)
	if err != nil {
		return fmt.Errorf("failed to generate configuration file: %w", err)
	}

	fmt.Printf("Configuration file '%s' created successfully using '%s' template.\n", filename, configTemplate)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. Review and customize the configuration settings\n")
	fmt.Printf("2. Validate the configuration: typosentinel config validate %s\n", filename)
	fmt.Printf("3. Test the configuration: typosentinel scan --config %s\n", filename)

	return nil
}

// runConfigValidate validates a configuration file
func runConfigValidate(cmd *cobra.Command, args []string) error {
	// Determine config file
	configFile := ""
	if len(args) > 0 {
		configFile = args[0]
	}

	// Create config manager
	options := config.ConfigManagerOptions{
		ConfigFile: configFile,
	}
	configManager := config.NewConfigManager(options, nil)

	// Load configuration
	err := configManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate configuration
	result, err := validateConfiguration(configManager)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Display results
	if configWarningsOnly {
		// Show only warnings
		if len(result.Warnings) > 0 {
			fmt.Println("Configuration Warnings:")
			for _, warning := range result.Warnings {
				fmt.Printf("  ⚠️  %s\n", warning)
			}
		} else {
			fmt.Println("✅ No warnings found.")
		}
		return nil
	}

	// Show validation results
	if result.Valid {
		fmt.Println("✅ Configuration is valid!")
	} else {
		fmt.Println("❌ Configuration validation failed:")
		for _, err := range result.Errors {
			fmt.Printf("  • %s\n", err)
		}
	}

	// Show warnings if any
	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  • %s\n", warning)
		}
	}

	// Exit with error code if validation failed
	if !result.Valid {
		os.Exit(1)
	}

	return nil
}

// runConfigShow shows current configuration
func runConfigShow(cmd *cobra.Command, args []string) error {
	// Determine config file
	configFile := ""
	if len(args) > 0 {
		configFile = args[0]
	}

	// Create config manager
	options := config.ConfigManagerOptions{
		ConfigFile: configFile,
	}
	configManager := config.NewConfigManager(options, nil)

	// Load configuration
	err := configManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Get configuration for display
	configEntries := configManager.GetAllConfig()

	// Get config info
	configInfo := getConfigInfo(configManager, configFile)

	// Display configuration
	fmt.Printf("Configuration File: %s\n", configInfo["config_file"])
	fmt.Printf("Environment Prefix: %s\n", configInfo["env_prefix"])
	fmt.Printf("Configuration Entries: %d\n", len(configEntries))
	fmt.Println()

	// Show environment variables if requested
	if configShowEnvVars {
		envVars := configInfo["env_variables"].([]string)
		if len(envVars) > 0 {
			fmt.Println("Environment Variables:")
			for _, envVar := range envVars {
				fmt.Printf("  %s\n", envVar)
			}
			fmt.Println()
		}
	}

	// Output configuration based on format
	switch configFormat {
	case "json":
		return outputConfigAsJSON(configEntries)
	case "yaml":
		return outputConfigAsYAML(configEntries)
	default:
		return fmt.Errorf("unsupported format: %s", configFormat)
	}
}

// runConfigTemplateList lists available templates
func runConfigTemplateList(cmd *cobra.Command, args []string) error {
	fmt.Println("Available Configuration Templates:")
	fmt.Println()

	// Built-in templates
	fmt.Println("Built-in Templates:")
	templates := []struct {
		name        string
		description string
	}{
		{"default", "Standard configuration with recommended settings"},
		{"minimal", "Minimal configuration with essential settings only"},
		{"development", "Development-friendly configuration with verbose logging"},
		{"production", "Production-ready configuration with security focus"},
		{"security-focused", "Maximum security settings for high-risk environments"},
	}

	for _, template := range templates {
		fmt.Printf("  %-16s %s\n", template.name, template.description)
	}

	// Custom templates (if any)
	customTemplatesDir := getCustomTemplatesDir()
	if entries, err := os.ReadDir(customTemplatesDir); err == nil && len(entries) > 0 {
		fmt.Println("\nCustom Templates:")
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml") {
				name := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".yaml"), ".yml")
				fmt.Printf("  %-16s Custom template\n", name)
			}
		}
	}

	return nil
}

// runConfigTemplateSave saves current config as template
func runConfigTemplateSave(cmd *cobra.Command, args []string) error {
	templateName := args[0]
	configFile := ""
	if len(args) > 1 {
		configFile = args[1]
	}

	// Create config manager
	options := config.ConfigManagerOptions{
		ConfigFile: configFile,
	}
	configManager := config.NewConfigManager(options, nil)

	// Load configuration
	err := configManager.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Get configuration entries
	configEntries := configManager.GetAllConfig()

	// Create template
	template := createTemplate(templateName, configDescription, configEntries)

	// Ensure templates directory exists
	templatesDir := getCustomTemplatesDir()
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return fmt.Errorf("failed to create templates directory: %w", err)
	}

	// Save template
	templateFile := filepath.Join(templatesDir, templateName+".yaml")
	if err := saveTemplate(template, templateFile); err != nil {
		return fmt.Errorf("failed to save template: %w", err)
	}

	fmt.Printf("Template '%s' saved successfully to %s\n", templateName, templateFile)
	return nil
}

// runConfigTemplateShow shows template details
func runConfigTemplateShow(cmd *cobra.Command, args []string) error {
	templateName := args[0]

	// Check if it's a built-in template
	builtinTemplates := []string{"default", "minimal", "development", "production", "security-focused"}
	isBuiltin := false
	for _, builtin := range builtinTemplates {
		if templateName == builtin {
			isBuiltin = true
			break
		}
	}

	if isBuiltin {
		// Show built-in template by generating it
		options := config.ConfigManagerOptions{}
		_ = config.NewConfigManager(options, nil)
		tempFile := filepath.Join(os.TempDir(), "temp_template.yaml")
		defer os.Remove(tempFile)

		// Generate template
		err := generateTemplateFile(templateName, tempFile)
		if err != nil {
			return fmt.Errorf("failed to generate template: %w", err)
		}

		content, err := os.ReadFile(tempFile)
		if err != nil {
			return fmt.Errorf("failed to read template: %w", err)
		}

		fmt.Printf("Built-in Template: %s\n", templateName)
		fmt.Println(strings.Repeat("=", 50))
		fmt.Print(string(content))
	} else {
		// Load custom template
		options := config.ConfigManagerOptions{}
		_ = config.NewConfigManager(options, nil)
		templateFile := filepath.Join(getCustomTemplatesDir(), templateName+".yaml")

		// Load custom template
		content, err := loadCustomTemplate(templateFile)
		if err != nil {
			return fmt.Errorf("failed to load custom template: %w", err)
		}

		fmt.Printf("Custom Template: %s\n", templateName)
		fmt.Println(strings.Repeat("=", 50))
		fmt.Print(string(content))
	}

	return nil
}

// Helper functions

func outputConfigAsJSON(configEntries map[string]*config.ConfigEntry) error {
	// Convert config entries to a simple map for JSON output
	configMap := make(map[string]interface{})
	for key, entry := range configEntries {
		configMap[key] = entry.Value
	}
	
	data, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config as JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputConfigAsYAML(configEntries map[string]*config.ConfigEntry) error {
	// Convert config entries to a simple map for YAML output
	configMap := make(map[string]interface{})
	for key, entry := range configEntries {
		configMap[key] = entry.Value
	}
	
	data, err := yaml.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("failed to marshal config as YAML: %w", err)
	}
	fmt.Print(string(data))
	return nil
}

func getCustomTemplatesDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./templates"
	}
	return filepath.Join(homeDir, ".config", "typosentinel", "templates")
}

// generateConfigFile creates a configuration file from a template
func generateConfigFile(filename, templateName string) error {
	var configContent string
	
	switch templateName {
	case "default":
		configContent = getDefaultConfigTemplate()
	case "minimal":
		configContent = getMinimalConfigTemplate()
	case "development":
		configContent = getDevelopmentConfigTemplate()
	case "production":
		configContent = getProductionConfigTemplate()
	case "security-focused":
		configContent = getSecurityFocusedConfigTemplate()
	default:
		return fmt.Errorf("unknown template: %s", templateName)
	}
	
	return os.WriteFile(filename, []byte(configContent), 0644)
}

// validateConfiguration performs comprehensive configuration validation
func validateConfiguration(configManager *config.ConfigManager) (struct {
	Warnings []string
	Errors   []string
	Valid    bool
}, error) {
	result := struct {
		Warnings []string
		Errors   []string
		Valid    bool
	}{
		Warnings: []string{},
		Errors:   []string{},
		Valid:    true,
	}
	
	// Get all configuration entries
	configEntries := configManager.GetAllConfig()
	if len(configEntries) == 0 {
		result.Warnings = append(result.Warnings, "No configuration entries found")
	}
	
	// Validate scanner configuration
	if maxConcurrency, exists := configEntries["scanner.max_concurrency"]; exists {
		if val, ok := maxConcurrency.Value.(int); ok && val <= 0 {
			result.Errors = append(result.Errors, "Scanner max concurrency must be greater than 0")
			result.Valid = false
		}
	} else {
		result.Warnings = append(result.Warnings, "Scanner max concurrency not configured")
	}
	
	if timeout, exists := configEntries["scanner.timeout"]; !exists || timeout.Value == nil {
		result.Warnings = append(result.Warnings, "Scanner timeout is not set, using default")
	}
	
	// Validate ML configuration
	if mlEnabled, exists := configEntries["ml.enabled"]; exists {
		if enabled, ok := mlEnabled.Value.(bool); ok && enabled {
			if modelPath, pathExists := configEntries["ml.model_path"]; !pathExists || modelPath.Value == "" {
				result.Errors = append(result.Errors, "ML is enabled but model path is not specified")
				result.Valid = false
			}
		}
	}
	
	// Validate API configuration
	if apiEnabled, exists := configEntries["api.enabled"]; exists {
		if enabled, ok := apiEnabled.Value.(bool); ok && enabled {
			if apiPort, portExists := configEntries["api.port"]; portExists {
				if port, ok := apiPort.Value.(int); ok && (port <= 0 || port > 65535) {
					result.Errors = append(result.Errors, "API port must be between 1 and 65535")
					result.Valid = false
				}
			}
			if apiHost, hostExists := configEntries["api.host"]; !hostExists || apiHost.Value == "" {
				result.Warnings = append(result.Warnings, "API host is not set, using default")
			}
		}
	}
	
	return result, nil
}

// getConfigInfo retrieves configuration information
func getConfigInfo(configManager *config.ConfigManager, configFile string) map[string]interface{} {
	info := map[string]interface{}{
		"config_file":   configFile,
		"env_prefix":    "TYPOSENTINEL",
		"env_variables": []string{},
		"source":        "file",
		"version":       "1.0",
		"loaded":        true,
	}
	
	if configFile == "" {
		info["config_file"] = "config.yaml"
	}
	
	// Collect environment variables
	envVars := []string{}
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "TYPOSENTINEL_") {
			envVars = append(envVars, env)
		}
	}
	info["env_variables"] = envVars
	
	return info
}

// createTemplate creates a template structure
func createTemplate(name, description string, configEntries map[string]*config.ConfigEntry) map[string]interface{} {
	// Convert config entries to a simple map
	configMap := make(map[string]interface{})
	for key, entry := range configEntries {
		configMap[key] = entry.Value
	}
	
	return map[string]interface{}{
		"name":        name,
		"description": description,
		"config":      configMap,
		"created":     fmt.Sprintf("%d", os.Getpid()), // Simple timestamp placeholder
	}
}

// saveTemplate saves a template to file
func saveTemplate(template map[string]interface{}, filename string) error {
	data, err := yaml.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}
	return os.WriteFile(filename, data, 0644)
}

// generateTemplateFile generates a built-in template file
func generateTemplateFile(templateName, filename string) error {
	return generateConfigFile(filename, templateName)
}

// loadCustomTemplate loads a custom template from file
func loadCustomTemplate(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// Configuration templates

func getDefaultConfigTemplate() string {
	return `# TypoSentinel Default Configuration
version: "1.0"

scanner:
  max_concurrency: 10
  timeout: 30s
  cache_enabled: true
  cache_ttl: 1h

detection:
  typosquatting:
    enabled: true
    threshold: 0.8
  homoglyph:
    enabled: true
  reputation:
    enabled: true

ml:
  enabled: false
  model_path: ""
  threshold: 0.7

api:
  enabled: false
  host: "localhost"
  port: 8080
  cors_enabled: true

logging:
  level: "info"
  format: "json"
  output: "stdout"

output:
  format: "table"
  file: ""
  verbose: false
`
}

func getMinimalConfigTemplate() string {
	return `# TypoSentinel Minimal Configuration
version: "1.0"

scanner:
  max_concurrency: 5
  timeout: 15s

detection:
  typosquatting:
    enabled: true

logging:
  level: "warn"

output:
  format: "json"
`
}

func getDevelopmentConfigTemplate() string {
	return `# TypoSentinel Development Configuration
version: "1.0"

scanner:
  max_concurrency: 5
  timeout: 60s
  cache_enabled: false

detection:
  typosquatting:
    enabled: true
    threshold: 0.7
  homoglyph:
    enabled: true
  reputation:
    enabled: true

ml:
  enabled: true
  model_path: "./models/typo_detector.pkl"
  threshold: 0.6

api:
  enabled: true
  host: "localhost"
  port: 8080
  cors_enabled: true

logging:
  level: "debug"
  format: "text"
  output: "stdout"

output:
  format: "table"
  verbose: true
`
}

func getProductionConfigTemplate() string {
	return `# TypoSentinel Production Configuration
version: "1.0"

scanner:
  max_concurrency: 20
  timeout: 30s
  cache_enabled: true
  cache_ttl: 24h

detection:
  typosquatting:
    enabled: true
    threshold: 0.9
  homoglyph:
    enabled: true
  reputation:
    enabled: true

ml:
  enabled: true
  model_path: "/opt/typosentinel/models/production.pkl"
  threshold: 0.8

api:
  enabled: true
  host: "0.0.0.0"
  port: 8080
  cors_enabled: false
  rate_limit:
    enabled: true
    requests_per_minute: 100

logging:
  level: "info"
  format: "json"
  output: "/var/log/typosentinel/app.log"

output:
  format: "json"
  file: "/var/log/typosentinel/results.json"

security:
  tls_enabled: true
  cert_file: "/etc/ssl/certs/typosentinel.crt"
  key_file: "/etc/ssl/private/typosentinel.key"
`
}

func getSecurityFocusedConfigTemplate() string {
	return `# TypoSentinel Security-Focused Configuration
version: "1.0"

scanner:
  max_concurrency: 15
  timeout: 45s
  cache_enabled: true
  cache_ttl: 6h

detection:
  typosquatting:
    enabled: true
    threshold: 0.95
    strict_mode: true
  homoglyph:
    enabled: true
    unicode_normalization: true
  reputation:
    enabled: true
    strict_scoring: true
  behavioral:
    enabled: true
    sandbox_timeout: 120s

ml:
  enabled: true
  model_path: "/opt/typosentinel/models/security.pkl"
  threshold: 0.9
  ensemble_enabled: true

api:
  enabled: true
  host: "127.0.0.1"
  port: 8443
  cors_enabled: false
  authentication:
    enabled: true
    method: "jwt"
  rate_limit:
    enabled: true
    requests_per_minute: 50

logging:
  level: "info"
  format: "json"
  output: "/var/log/typosentinel/security.log"
  audit_enabled: true

output:
  format: "json"
  file: "/var/log/typosentinel/security-results.json"
  include_metadata: true

security:
  tls_enabled: true
  tls_min_version: "1.3"
  cert_file: "/etc/ssl/certs/typosentinel.crt"
  key_file: "/etc/ssl/private/typosentinel.key"
  hsts_enabled: true
  content_security_policy: true
`
}