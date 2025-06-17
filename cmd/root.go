package cmd

import (
	"github.com/spf13/cobra"
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