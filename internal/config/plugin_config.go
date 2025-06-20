package config

// PluginConfig contains plugin system configuration
type PluginConfig struct {
	// Enable plugin system
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	
	// Directory containing plugin files
	PluginDirectory string `mapstructure:"plugin_directory" yaml:"plugin_directory"`
	
	// Auto-load plugins on startup
	AutoLoad bool `mapstructure:"auto_load" yaml:"auto_load"`
	
	// Plugin loading timeout (in seconds)
	LoadTimeout int `mapstructure:"load_timeout" yaml:"load_timeout"`
	
	// Maximum number of plugins to load
	MaxPlugins int `mapstructure:"max_plugins" yaml:"max_plugins"`
	
	// Plugin validation settings
	Validation PluginValidationConfig `mapstructure:"validation" yaml:"validation"`
	
	// Plugin security settings
	Security PluginSecurityConfig `mapstructure:"security" yaml:"security"`
	
	// Specific plugins to load
	Plugins []PluginEntry `mapstructure:"plugins" yaml:"plugins"`
}

// PluginValidationConfig contains plugin validation settings
type PluginValidationConfig struct {
	// Enable validation
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	
	// Check plugin signature
	CheckSignature bool `mapstructure:"check_signature" yaml:"check_signature"`
	
	// Required metadata fields
	RequiredMetadata []string `mapstructure:"required_metadata" yaml:"required_metadata"`
	
	// Allowed file extensions
	AllowedExtensions []string `mapstructure:"allowed_extensions" yaml:"allowed_extensions"`
}

// PluginSecurityConfig contains plugin security settings
type PluginSecurityConfig struct {
	// Sandbox plugins (if supported)
	Sandboxed bool `mapstructure:"sandboxed" yaml:"sandboxed"`
	
	// Allowed paths for plugin access
	AllowedPaths []string `mapstructure:"allowed_paths" yaml:"allowed_paths"`
	
	// Restricted APIs
	RestrictedAPIs []string `mapstructure:"restricted_apis" yaml:"restricted_apis"`
	
	// Maximum memory usage
	MaxMemoryUsage string `mapstructure:"max_memory_usage" yaml:"max_memory_usage"`
	
	// Maximum execution time (in seconds)
	MaxExecutionTime int `mapstructure:"max_execution_time" yaml:"max_execution_time"`
}

// PluginEntry represents a specific plugin configuration
type PluginEntry struct {
	// Plugin name
	Name string `mapstructure:"name" yaml:"name"`
	
	// Plugin file path
	Path string `mapstructure:"path" yaml:"path"`
	
	// Plugin enabled status
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	
	// Plugin configuration
	Config map[string]interface{} `mapstructure:"config" yaml:"config"`
	
	// Plugin priority (for loading order)
	Priority int `mapstructure:"priority" yaml:"priority"`
}