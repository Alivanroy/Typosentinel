package cmd

import (
	"github.com/spf13/cobra"
)

var (
	configFile   string
	verbose      bool
	outputFormat string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "typosentinel",
	Short: "TypoSentinel - Intelligent supply chain security scanner",
	Long: `TypoSentinel is an intelligent supply chain firewall that actively blocks 
malicious packages, typosquatting attacks, and supply chain threats in real-time.

It provides:
- Multi-language package support (npm, PyPI, Go, Maven, NuGet, etc.)
- Advanced threat detection algorithms (RUNT, DIRT, GTR)  
- Policy-based security enforcement
- SBOM generation (SPDX, CycloneDX)
- Graph visualization (DOT, SVG, Mermaid)
- CI/CD integration`,
}

func init() {
	// Global flags
	RootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file (default is $HOME/.planfinale.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "futuristic", "output format (json, yaml, table, futuristic)")
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return RootCmd.Execute()
}
