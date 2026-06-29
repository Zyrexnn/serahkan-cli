package cmd

import (
	"fmt"
	"runtime"

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
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "serahkan %s\n", Version)
		fmt.Fprintf(out, "commit: %s\n", Commit)
		fmt.Fprintf(out, "built: %s\n", Date)
		fmt.Fprintf(out, "go: %s\n", runtime.Version())
		fmt.Fprintf(out, "os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
