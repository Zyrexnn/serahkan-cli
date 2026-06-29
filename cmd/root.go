package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "serahkan",
	Short:        "AI-powered bug bounty and pentesting CLI wrapper",
	SilenceUsage: true,
	Version:      Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
