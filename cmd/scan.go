package cmd

import (
	"fmt"
	"strings"

	"github.com/Zyrexnn/serahkan-cli/internal/ai"
	"github.com/Zyrexnn/serahkan-cli/internal/parser"
	"github.com/Zyrexnn/serahkan-cli/internal/runner"
	"github.com/spf13/cobra"
)

var scanOptions struct {
	target   string
	model    string
	severity string
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a Nuclei scan against a target",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()

		rawOutput, err := runner.RunNuclei(cmd.Context(), scanOptions.target)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		allowedSeverities := parseSeverityFlag(scanOptions.severity)

		findings, err := parser.ParseAndFilter(rawOutput, allowedSeverities)
		if err != nil {
			return fmt.Errorf("failed to parse nuclei output: %w", err)
		}

		if len(findings) == 0 {
			fmt.Fprintf(out, "No vulnerabilities matching severity levels [%s] were detected.\n", strings.Join(allowedSeverities, ", "))
			return nil
		}

		summary, err := formatFindingsSummary(findings)
		if err != nil {
			return fmt.Errorf("failed to format findings summary: %w", err)
		}

		analysis, err := ai.SendToLocalAI(summary, scanOptions.model)
		if err != nil {
			return fmt.Errorf("AI analysis failed: %w", err)
		}

		fmt.Fprintln(out, "------------------------------------------------------------")
		fmt.Fprintln(out, "Local AI Vulnerability Analysis")
		fmt.Fprintln(out, "------------------------------------------------------------")
		fmt.Fprintln(out, strings.TrimSpace(analysis))
		fmt.Fprintln(out, "------------------------------------------------------------")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOptions.target, "target", "t", "", "Target URL to scan")
	scanCmd.Flags().StringVar(&scanOptions.model, "model", "qwen2.5-coder:1.5b", "Local LLM model name")
	scanCmd.Flags().StringVar(&scanOptions.severity, "severity", "medium,high,critical", "Severity levels to include")
	_ = scanCmd.MarkFlagRequired("target")
}

func parseSeverityFlag(value string) []string {
	parts := strings.Split(value, ",")
	severities := make([]string, 0, len(parts))

	for _, part := range parts {
		severity := strings.ToLower(strings.TrimSpace(part))
		if severity != "" {
			severities = append(severities, severity)
		}
	}

	if len(severities) == 0 {
		return []string{"high", "critical"}
	}

	return severities
}

func formatFindingsSummary(findings []parser.NucleiFinding) (string, error) {
	var builder strings.Builder
	builder.WriteString("Filtered Nuclei findings requiring defensive analysis:\n")

	for index, finding := range findings {
		fmt.Fprintf(&builder, "\nFinding %d\n", index+1)
		fmt.Fprintf(&builder, "Template ID: %s\n", finding.TemplateID)
		fmt.Fprintf(&builder, "Name: %s\n", finding.Name)
		fmt.Fprintf(&builder, "Severity: %s\n", finding.Severity)
		fmt.Fprintf(&builder, "Matched At: %s\n", finding.MatchedAt)

		if finding.Info.Description != "" {
			fmt.Fprintf(&builder, "Description: %s\n", finding.Info.Description)
		}

		if len(finding.ExtractedResults) > 0 {
			fmt.Fprintf(&builder, "Extracted Results: %s\n", strings.Join(finding.ExtractedResults, ", "))
		}
	}

	return builder.String(), nil
}
