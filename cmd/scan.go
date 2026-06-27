package cmd

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/ai"
	"github.com/Zyrexnn/serahkan-cli/internal/parser"
	"github.com/Zyrexnn/serahkan-cli/internal/runner"
	"github.com/spf13/cobra"
)

var scanOptions struct {
	target        string
	severity      string
	timeout       int
	retries       int
	verbose       bool
	noInteractsh  bool
	aiEndpoint    string
	aiModel       string
	aiApiKey      string
	aiTimeout     int
	limit         int
}

var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a Nuclei scan against a target",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		logOut := cmd.ErrOrStderr()

		// Validate target URL and scheme
		if err := validateTarget(scanOptions.target); err != nil {
			return err
		}

		allowedSeverities := parseSeverityFlag(scanOptions.severity)

		fmt.Fprintf(logOut, " [SCAN] Running automated vulnerability scanning on %s...\n", scanOptions.target)
		stopTicker := startScanTicker(logOut, scanOptions.target)

		// Set runner options
		runOptions := runner.Options{
			TimeoutSeconds: scanOptions.timeout,
			Retries:        scanOptions.retries,
			Verbose:        scanOptions.verbose,
			NoInteractsh:   scanOptions.noInteractsh,
			LogWriter:      logOut,
		}

		findings, err := runner.RunNuclei(cmd.Context(), scanOptions.target, allowedSeverities, runOptions)
		stopTicker()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		fmt.Fprintln(logOut, " [PARSER] Log filtering completed. Analyzing severity payload...")

		if len(findings) == 0 {
			fmt.Fprintln(out)
			fmt.Fprintf(out, "[SUCCESS] Scan complete. No vulnerabilities matching severity levels [%s] detected on %s.\n", strings.Join(allowedSeverities, ", "), scanOptions.target)
			fmt.Fprintln(out)
			return nil
		}

		// Sort, truncate, and limit findings summary before sending to AI
		summary, err := formatFindingsSummary(findings, scanOptions.limit)
		if err != nil {
			return fmt.Errorf("failed to format findings summary: %w", err)
		}

		// Limit the findings slice for the fallback validator to use
		if len(findings) > scanOptions.limit {
			findings = findings[:scanOptions.limit]
		}

		fmt.Fprintln(logOut, " [AI] Local LLM is generating defensive analysis and remediation code...")

		// Set up AI client configuration
		aiConfig := ai.DefaultConfig()
		if scanOptions.aiEndpoint != "" {
			aiConfig.Endpoint = scanOptions.aiEndpoint
		}
		if scanOptions.aiModel != "" {
			aiConfig.Model = scanOptions.aiModel
		}
		if scanOptions.aiApiKey != "" {
			aiConfig.ApiKey = scanOptions.aiApiKey
		}
		if scanOptions.aiTimeout > 0 {
			aiConfig.Timeout = time.Duration(scanOptions.aiTimeout) * time.Second
		}

		analysis, aiErr := ai.SendToLocalAI(cmd.Context(), summary, aiConfig)
		if aiErr != nil {
			fmt.Fprintf(logOut, " [WARN] AI analysis unavailable (%v). Showing findings report without AI analysis.\n", aiErr)
			analysis = "" // triggers fallback below
		}

		// Validate structure of LLM response, fallback if malformed
		validatedReport := validateAndFallbackAIOutput(analysis, findings)

		fmt.Fprintln(out)
		fmt.Fprintln(out, "================================================================================")
		fmt.Fprintln(out, "                       AI DEFENSIVE ANALYSIS REPORT                             ")
		fmt.Fprintln(out, "================================================================================")
		fmt.Fprintln(out, strings.TrimSpace(validatedReport))
		fmt.Fprintln(out, "================================================================================")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOptions.target, "target", "t", "", "Target URL to scan (e.g. http://example.com)")
	scanCmd.Flags().StringVar(&scanOptions.severity, "severity", "medium,high,critical", "Severity levels to include")
	scanCmd.Flags().IntVar(&scanOptions.timeout, "timeout", 30, "Timeout in seconds per Nuclei HTTP request")
	scanCmd.Flags().IntVar(&scanOptions.retries, "retries", 2, "Number of retries for Nuclei scan")
	scanCmd.Flags().BoolVarP(&scanOptions.verbose, "verbose", "v", false, "Show verbose debug logging on stderr")
	scanCmd.Flags().BoolVar(&scanOptions.noInteractsh, "no-interactsh", false, "Disable out-of-band interaction templates (-ni). Reduces coverage but avoids interactsh dependency")
	scanCmd.Flags().StringVar(&scanOptions.aiEndpoint, "ai-endpoint", "", "Local AI completion endpoint (overrides SERAHKAN_AI_ENDPOINT)")
	scanCmd.Flags().StringVar(&scanOptions.aiModel, "ai-model", "", "Local AI model name (overrides SERAHKAN_AI_MODEL)")
	scanCmd.Flags().StringVar(&scanOptions.aiApiKey, "ai-api-key", "", "API key for AI endpoint (overrides SERAHKAN_AI_API_KEY). Required for cloud endpoints.")
	scanCmd.Flags().IntVar(&scanOptions.aiTimeout, "ai-timeout", 120, "Timeout in seconds for AI completions")
	scanCmd.Flags().IntVar(&scanOptions.limit, "limit", 10, "Maximum number of findings to send to AI for analysis")

	_ = scanCmd.MarkFlagRequired("target")
}

func validateTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid target: scheme %q is not supported. Target must start with http:// or https:// (example: http://example.com)", u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("invalid target: host/domain name is missing")
	}

	return nil
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

func formatFindingsSummary(findings []parser.NucleiFinding, maxFindings int) (string, error) {
	var builder strings.Builder
	builder.WriteString("Filtered Nuclei findings requiring defensive analysis:\n")

	// Sort findings by severity (critical -> high -> medium -> low -> info)
	sort.Slice(findings, func(i, j int) bool {
		return severityRank[strings.ToLower(findings[i].Severity)] > severityRank[strings.ToLower(findings[j].Severity)]
	})

	displayCount := len(findings)
	if displayCount > maxFindings {
		displayCount = maxFindings
	}

	for i := 0; i < displayCount; i++ {
		finding := findings[i]
		fmt.Fprintf(&builder, "\nFinding %d\n", i+1)
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
		} else {
			fmt.Fprintf(&builder, "Curl Command: Not available\n")
		}

		if len(finding.ExtractedResults) > 0 {
			fmt.Fprintf(&builder, "Extracted Results: %s\n", strings.Join(finding.ExtractedResults, ", "))
		}

		if finding.Request != "" {
			req := finding.Request
			if len(req) > 1000 {
				req = req[:1000] + "\n... [TRUNCATED]"
			}
			fmt.Fprintf(&builder, "Request: %s\n", req)
		}

		if finding.Response != "" {
			resp := finding.Response
			if len(resp) > 1000 {
				resp = resp[:1000] + "\n... [TRUNCATED]"
			}
			fmt.Fprintf(&builder, "Response: %s\n", resp)
		}
	}

	return builder.String(), nil
}

func validateAndFallbackAIOutput(analysis string, findings []parser.NucleiFinding) string {
	hasProfile := strings.Contains(analysis, "[=] TARGET PROFILE")
	hasRootCause := strings.Contains(analysis, "[=] ROOT CAUSE ANALYSIS")
	hasRemediation := strings.Contains(analysis, "[=] REMEDIATION & HARDENING PLAYBOOK")

	if hasProfile && hasRootCause && hasRemediation {
		return analysis
	}

	var fb strings.Builder
	fb.WriteString("+-------------------------------------------------------------------------+\n")
	fb.WriteString("|                AI DEFENSIVE ANALYSIS REPORT (FALLBACK)                  |\n")
	fb.WriteString("+-------------------------------------------------------------------------+\n\n")
	fb.WriteString("[=] TARGET PROFILE\n")
	if len(findings) > 0 {
		fb.WriteString(fmt.Sprintf("    - Target Host : %s\n", findings[0].Host))
	}
	fb.WriteString("    - Risk Status : HIGH ALERT\n\n")
	fb.WriteString("[=] ROOT CAUSE ANALYSIS\n")
	fb.WriteString("    The local AI model did not output the standard structured report format.\n")
	fb.WriteString("    Below is a fallback technical summary of the parsed vulnerabilities:\n\n")

	for i, f := range findings {
		fb.WriteString(fmt.Sprintf("[!] FINDING %d: %s\n", i+1, f.Name))
		fb.WriteString(fmt.Sprintf("    - Risk Level  : %s\n", f.Severity))
		fb.WriteString(fmt.Sprintf("    - Matched At  : %s\n", f.MatchedAt))
		if f.Info.Description != "" {
			fb.WriteString(fmt.Sprintf("    - Technical Overview: %s\n", f.Info.Description))
		}
		if f.CurlCommand != "" {
			fb.WriteString(fmt.Sprintf("    - Manual Proof-of-Concept Validation:\n      * Execute Command:\n        $ %s\n", f.CurlCommand))
		} else {
			fb.WriteString("    - Manual Proof-of-Concept Validation:\n      * Execute Command:\n        $ N/A (No validation curl command available)\n")
		}
		fb.WriteString("---------------------------------------------------------------------------\n")
	}

	fb.WriteString("\n[=] REMEDIATION & HARDENING PLAYBOOK\n")
	fb.WriteString("    - Targeted Component: Web Application / Web Server\n")
	fb.WriteString("    - General Remediation guidelines:\n")
	fb.WriteString("      1. Sanitize, filter and validate all inputs on server-side.\n")
	fb.WriteString("      2. Implement contextual output encoding before rendering dynamic values in HTML templates.\n")
	fb.WriteString("      3. Implement secure headers (e.g., Content-Security-Policy, X-Frame-Options).\n")
	fb.WriteString("      4. Keep packages, dependencies, and servers updated to patch known vulnerabilities.\n")

	return fb.String()
}
