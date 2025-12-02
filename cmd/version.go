package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Run: func(cmd *cobra.Command, args []string) {
		// Version info would typically come from build ldflags
		// For now, using a placeholder
		println("TypoSentinel v1.0.0")
		println("Build: dev")
		println("Commit: latest")
	},
}
