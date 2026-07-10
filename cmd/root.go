package cmd

import (
	"fmt"
	"os"

	"github.com/Zyrexnn/serahkan-cli/internal/style"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "serahkan",
	Short:         "SERAHKAN CLI - AI-powered web security scanner",
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       Version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if cmd.Name() != "version" {
			style.PrintBanner(cmd.ErrOrStderr(), Version)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, style.Red.Sprint(err))
		os.Exit(1)
	}
}
