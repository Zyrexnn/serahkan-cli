package cmd

import (
	"fmt"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/ai"
	"github.com/Zyrexnn/serahkan-cli/internal/doctor"
	"github.com/Zyrexnn/serahkan-cli/internal/style"
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

		style.PrintDoctorHeader(out)

		hasFailure := false
		for _, result := range results {
			style.PrintDoctorResult(out, result.Status, result.Name, result.Details, result.DebugLines, doctorVerbose)
			if result.Status != "OK" {
				hasFailure = true
			}
		}

		style.PrintDoctorFooter(out, hasFailure)

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
