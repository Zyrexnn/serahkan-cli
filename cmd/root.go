package cmd

import (
	"os"

	"github.com/Zyrexnn/serahkan-cli/internal/style"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "serahkan",
	Short:        "AI-powered bug bounty and pentesting CLI wrapper",
	SilenceUsage: true,
	SilenceErrors: true,
	Version:      Version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if cmd.Name() != "version" {
			style.PrintBanner(cmd.ErrOrStderr(), Version)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
