package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/exporter"
	"github.com/Zyrexnn/serahkan-cli/internal/style"
	"github.com/spf13/cobra"
)

type reportOptions struct {
	input  string
	format string
	output string
}

var reportOpts reportOptions

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Re-render a saved JSON scan report to HTML or Markdown",
	Long: `Read a JSON scan report (saved with --output json) and export it
as an HTML or Markdown file without re-running the scan.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()

		data, err := os.ReadFile(reportOpts.input)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		var report scanJSONReport
		if err := json.Unmarshal(data, &report); err != nil {
			return fmt.Errorf("failed to parse JSON report: %w", err)
		}

		format := strings.ToLower(strings.TrimSpace(reportOpts.format))
		if format == "" {
			format = "html"
		}

		if format != "html" && format != "markdown" {
			return fmt.Errorf("unsupported format %q, use html or markdown", format)
		}

		targetLabel := report.Target
		scanDuration := fmt.Sprintf("%ds", report.DurationSeconds)
		if report.DurationSeconds == 0 {
			scanDuration = "unknown"
		}

		ais := report.AIAnalysis
		if ais == "" {
			ais = "No AI analysis available"
		}

		var summaryBuilder strings.Builder
		summaryBuilder.WriteString(fmt.Sprintf("Target: %s\n", targetLabel))
		summaryBuilder.WriteString(fmt.Sprintf("Findings: %d\n", report.FindingCount))
		summaryBuilder.WriteString(fmt.Sprintf("Severities: %s\n", strings.Join(report.Severities, ", ")))
		summaryBuilder.WriteString(fmt.Sprintf("Duration: %s\n", scanDuration))
		summaryBuilder.WriteString(fmt.Sprintf("AI Status: %s\n", report.AIStatus))
		summaryBuilder.WriteString(fmt.Sprintf("Profile: %s\n", report.Profile))
		if report.Focus != "" {
			summaryBuilder.WriteString(fmt.Sprintf("Focus: %s\n", report.Focus))
		}
		summaryBuilder.WriteString(fmt.Sprintf("Auth Mode: %s\n", report.AuthMode))
		if len(report.SkippedReasons) > 0 {
			summaryBuilder.WriteString("\nCoverage Notes:\n")
			for _, r := range report.SkippedReasons {
				summaryBuilder.WriteString(fmt.Sprintf("  - %s\n", r))
			}
		}

		exportData := exporter.ReportData{
			Target:       targetLabel,
			Findings:     ais,
			AISummary:    summaryBuilder.String() + "\n" + ais,
			ScanDuration: scanDuration,
			Timestamp:    time.Unix(report.GeneratedAtUnixUTC, 0),
			FindingCount: report.FindingCount,
			AIUsed:       report.AIUsed,
			AIStatus:     report.AIStatus,
			Version:      Version,
		}

		var savedPath string
		var exportErr error
		if format == "html" {
			savedPath, exportErr = exporter.ExportHTML(exportData)
		} else {
			savedPath, exportErr = exporter.ExportMarkdown(exportData)
		}

		if exportErr != nil {
			return fmt.Errorf("export failed: %w", exportErr)
		}

		if reportOpts.output != "" {
			if err := os.Rename(savedPath, reportOpts.output); err != nil {
				fmt.Fprintf(out, "exported to %s\n", savedPath)
			} else {
				savedPath = reportOpts.output
			}
		}

		fmt.Fprintf(out, "%s report saved to %s\n", style.TagOK, style.Target(savedPath))
		return nil
	},
}

func init() {
	reportCmd.Flags().StringVarP(&reportOpts.input, "input", "i", "", "Path to JSON scan report (required)")
	reportCmd.Flags().StringVarP(&reportOpts.format, "format", "f", "html", "Output format: html or markdown")
	reportCmd.Flags().StringVarP(&reportOpts.output, "output", "o", "", "Custom output file path (optional)")
	reportCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(reportCmd)
}
