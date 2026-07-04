package cmd

import (
	"runtime"

	"github.com/Zyrexnn/serahkan-cli/internal/style"
	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print build and runtime version information",
	Run: func(cmd *cobra.Command, args []string) {
		style.PrintVersionInfo(cmd.OutOrStdout(), Version, Commit, Date, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
