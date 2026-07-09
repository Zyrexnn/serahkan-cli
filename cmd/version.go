package cmd

import (
	"fmt"
	"runtime"

	"github.com/Zyrexnn/serahkan-cli/internal/style"
	"github.com/spf13/cobra"

	"github.com/Zyrexnn/serahkan-cli/internal/runner"
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

		nucleiVersion, err := runner.ResolveNucleiVersion()
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %s\n", style.DimWhite.Sprint("nuclei :"), style.Dim("not found"))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %s\n", style.DimWhite.Sprint("nuclei :"), style.Green.Sprint("v"+nucleiVersion))
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
