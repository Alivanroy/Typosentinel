package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"typosentinel/internal/config"
	"typosentinel/pkg/logger"
)

var (
	// Global flags
	cfgFile string
	debug   bool
	verbose bool
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
	PersistentPreRunE: initializeConfig,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Note: init function moved to cmd.go to avoid duplication

// initializeConfig initializes the configuration and logger
func initializeConfig(cmd *cobra.Command, args []string) error {
	// Initialize logger with basic settings first
	logger.InitDefault()

	// Override log level based on flags
	if debug {
		logger.SetGlobalLevel(logger.DEBUG)
		logger.Debug("Debug mode enabled")
	} else if verbose {
		logger.SetGlobalLevel(logger.INFO)
	}

	// Load full configuration
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		logger.Warn("Failed to unmarshal configuration, using defaults", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		// Initialize logger with loaded configuration
		if cfg.Logging.Level != "" {
			loggerConfig := logger.LoggerConfig{
				Level:    cfg.Logging.Level,
				Format:   cfg.Logging.Format,
				Output:   cfg.Logging.Output,
				Rotation: logger.RotationConfig{
					Enabled:    cfg.Logging.Rotation.Enabled,
					MaxSize:    cfg.Logging.Rotation.MaxSize,
					MaxBackups: cfg.Logging.Rotation.MaxBackups,
					MaxAge:     cfg.Logging.Rotation.MaxAge,
				},
			}
			if err := logger.InitFromConfig(loggerConfig); err != nil {
				logger.Warn("Failed to initialize logger from config", map[string]interface{}{
				"error": err.Error(),
			})
			}
		}

		// Override log level again if flags are set
		if debug {
			logger.SetGlobalLevel(logger.DEBUG)
		} else if verbose {
			logger.SetGlobalLevel(logger.INFO)
		}

		logger.Info("Configuration loaded successfully", map[string]interface{}{
			"config_file": viper.ConfigFileUsed(),
		})
	}

	logger.Debug("Logger initialized")

	return nil
}