package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/ai"
	"github.com/Zyrexnn/serahkan-cli/internal/parser"
	"github.com/Zyrexnn/serahkan-cli/internal/runner"
	"github.com/spf13/cobra"
)

var scanOptions struct {
	target   string
	severity string
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a Nuclei scan against a target",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		allowedSeverities := parseSeverityFlag(scanOptions.severity)

		fmt.Fprintf(out, " [SCAN] Running automated vulnerability scanning on %s...\n", scanOptions.target)
		stopTicker := startScanTicker(out, scanOptions.target)
		findings, err := runner.RunNuclei(cmd.Context(), scanOptions.target, allowedSeverities)
		stopTicker()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		fmt.Fprintln(out, " [PARSER] Log filtering completed. Analyzing severity payload...")

		if len(findings) == 0 {
			fmt.Fprintln(out)
			fmt.Fprintf(out, "[SUCCESS] Scan complete. No vulnerabilities matching severity levels [%s] detected on %s.\n", strings.Join(allowedSeverities, ", "), scanOptions.target)
			fmt.Fprintln(out)
			return nil
		}

		summary, err := formatFindingsSummary(findings)
		if err != nil {
			return fmt.Errorf("failed to format findings summary: %w", err)
		}

		fmt.Fprintln(out, " [AI] Local LLM is generating defensive analysis and remediation code...")
		analysis, err := ai.SendToLocalAI(summary)
		if err != nil {
			return fmt.Errorf("AI analysis failed: %w", err)
		}

		fmt.Fprintln(out)
		fmt.Fprintln(out, "================================================================================")
		fmt.Fprintln(out, "                       AI DEFENSIVE ANALYSIS REPORT                             ")
		fmt.Fprintln(out, "================================================================================")
		fmt.Fprintln(out, strings.TrimSpace(analysis))
		fmt.Fprintln(out, "================================================================================")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOptions.target, "target", "t", "", "Target URL to scan")
	scanCmd.Flags().StringVar(&scanOptions.severity, "severity", "medium,high,critical", "Severity levels to include")
	_ = scanCmd.MarkFlagRequired("target")
}

func startScanTicker(out io.Writer, target string) func() {
	done := make(chan struct{})
	finished := make(chan struct{})

	go func() {
		defer close(finished)

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		elapsed := 0
		for {
			select {
			case <-ticker.C:
				elapsed += 10
				fmt.Fprintf(out, " [SCAN] Active for %ds on %s; first run may download templates.\n", elapsed, target)
			case <-done:
				return
			}
		}
	}()

	return func() {
		close(done)
		<-finished
	}
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

		if finding.Host != "" {
			fmt.Fprintf(&builder, "Host: %s\n", finding.Host)
		}

		if finding.Info.Description != "" {
			fmt.Fprintf(&builder, "Description: %s\n", finding.Info.Description)
		}

		if finding.CurlCommand != "" {
			fmt.Fprintf(&builder, "Curl Command: %s\n", finding.CurlCommand)
		}

		if len(finding.ExtractedResults) > 0 {
			fmt.Fprintf(&builder, "Extracted Results: %s\n", strings.Join(finding.ExtractedResults, ", "))
		}

		if finding.Request != "" {
			fmt.Fprintf(&builder, "Request: %s\n", finding.Request)
		}

		if finding.Response != "" {
			fmt.Fprintf(&builder, "Response: %s\n", finding.Response)
		}
	}

	return builder.String(), nil
}
