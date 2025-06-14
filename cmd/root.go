package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/typosentinel/typosentinel/internal/config"
)

var (
	// Global flags
	cfgFile string
	debug   bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "typosentinel",
	Short: "Advanced typosquatting detection and package security scanner",
	Long: `TypoSentinel is a comprehensive security tool designed to detect typosquatting
attacks and malicious packages across multiple package registries.

It combines multiple analysis engines including:
- Static code analysis for suspicious patterns
- Dynamic behavior analysis in sandboxed environments  
- Machine learning-based similarity detection
- Software provenance and integrity verification

TypoSentinel helps developers and security teams identify potentially
malicious packages that attempt to impersonate legitimate ones through
typosquatting, dependency confusion, and other supply chain attacks.

Example usage:
  typosentinel scan lodash
  typosentinel scan --registry pypi requests
  typosentinel scan --local ./package.json
  typosentinel monitor --config monitoring.yaml
  typosentinel database update`,
	Version: "1.0.0",
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.typosentinel/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug mode")

	// Bind flags to viper
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".typosentinel" (without extension).
		configDir := filepath.Join(home, ".typosentinel")
		viper.AddConfigPath(configDir)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	// Environment variables
	viper.SetEnvPrefix("TYPOSENTINEL")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if debug {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	} else {
		// Create default config if none exists
		if cfgFile == "" {
			if err := createDefaultConfig(); err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "Warning: failed to create default config: %v\n", err)
				}
			}
		}
	}

	// Set debug mode
	if debug {
		viper.Set("core.debug", true)
		viper.Set("logging.level", "debug")
	}
}

// createDefaultConfig creates a default configuration file if none exists.
func createDefaultConfig() error {
	// Ensure config directory exists
	if err := config.EnsureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config file already exists
	configPath := filepath.Join(config.GetConfigDir(), "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return nil // Config already exists
	}

	// Create default configuration
	defaultConfig := config.DefaultEnhancedConfig()

	// Convert to YAML
	yamlData, err := defaultConfig.ToYAML()
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "Created default config file: %s\n", configPath)
	}

	return nil
}