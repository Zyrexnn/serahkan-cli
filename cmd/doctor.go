package cmd

import (
	"fmt"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/ai"
	"github.com/Zyrexnn/serahkan-cli/internal/doctor"
	"github.com/spf13/cobra"
)

var doctorVerbose bool

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check required local dependencies and configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()

		aiConfig := ai.DefaultConfig()
		aiConfig.Timeout = 5 * time.Second

		results := []doctor.CheckResult{
			doctor.CheckNuclei(),
			doctor.CheckAI(cmd.Context(), aiConfig),
		}

		fmt.Fprintln(out, "serahkan doctor")
		fmt.Fprintln(out, "----------------")

		hasFailure := false
		for _, result := range results {
			fmt.Fprintf(out, "%-6s %-8s %s\n", "["+result.Status+"]", result.Name, result.Details)
			if doctorVerbose {
				for _, line := range result.DebugLines {
					fmt.Fprintf(out, "       %-8s %s\n", "", line)
				}
			}
			if result.Status != "OK" {
				hasFailure = true
			}
		}

		fmt.Fprintln(out)
		fmt.Fprintln(out, "config precedence: flag > env > config file > default")

		if hasFailure {
			return fmt.Errorf("doctor checks failed")
		}

		return nil
	},
}

func init() {
	doctorCmd.Flags().BoolVarP(&doctorVerbose, "verbose", "v", false, "Show detailed diagnostics for each doctor check")
	rootCmd.AddCommand(doctorCmd)
}
