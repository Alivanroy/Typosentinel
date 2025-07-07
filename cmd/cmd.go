package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.typosentinel.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug mode")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose logging")
	rootCmd.PersistentFlags().BoolVar(&trace, "trace", false, "enable trace mode (most verbose)")
	rootCmd.PersistentFlags().StringVar(&debugMode, "debug-mode", "", "set debug mode (basic, verbose, trace, performance, security)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "set log level (trace, verbose, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "", "set log format (text, json)")
	rootCmd.PersistentFlags().StringVar(&logOutput, "log-output", "", "set log output (stdout, stderr, file path)")

	// Commands are added in their respective init() functions
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
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".typosentinel")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		// Config file loaded successfully
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
