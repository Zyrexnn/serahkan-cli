package cmd

import (
	"context"
	"encoding/json"
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
	target                    string
	severity                  string
	profile                   string
	timeout                   int
	scanTimeout               int
	retries                   int
	verbose                   bool
	noInteractsh              bool
	includeHTTP               bool
	includeLowInfo            bool
	includeOOB                bool
	enableHeadless            bool
	enableDAST                bool
	automaticScan             bool
	includeDefaultIgnoredTags []string
	legacyCompatible          bool
	showNucleiCommand         bool
	headers                   []string
	cookie                    string
	cookieFile                string
	tags                      []string
	excludeTags               []string
	templates                 []string
	workflows                 []string
	types                     []string
	skipAI                    bool
	aiEndpoint                string
	aiModel                   string
	aiApiKey                  string
	aiTimeout                 int
	limit                     int
	output                    string
}

var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

const maxAISummaryChars = 6000

type scanJSONReport struct {
	Target             string                 `json:"target"`
	Severities         []string               `json:"severities"`
	FindingCount       int                    `json:"finding_count"`
	RawFindings        int                    `json:"raw_findings"`
	FilteredFindings   int                    `json:"filtered_findings"`
	SkippedReasons     []string               `json:"skipped_reasons,omitempty"`
	Profile            string                 `json:"profile"`
	NucleiCommand      []string               `json:"nuclei_command,omitempty"`
	AIUsed             bool                   `json:"ai_used"`
	AIStatus           string                 `json:"ai_status"`
	AIError            string                 `json:"ai_error,omitempty"`
	AIAnalysis         string                 `json:"ai_analysis,omitempty"`
	Findings           []parser.NucleiFinding `json:"findings"`
	DurationSeconds    int64                  `json:"duration_seconds"`
	GeneratedAtUnixUTC int64                  `json:"generated_at_unix_utc"`
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a Nuclei scan against a target",
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		logOut := cmd.ErrOrStderr()
		startedAt := time.Now()

		applyScanProfile(cmd)

		if err := validateTarget(scanOptions.target); err != nil {
			return err
		}
		if err := validateOutputMode(scanOptions.output); err != nil {
			return err
		}
		if err := validateScanProfile(scanOptions.profile); err != nil {
			return err
		}

		allowedSeverities := parseSeverityFlag(scanOptions.severity)
		if scanOptions.includeLowInfo {
			allowedSeverities = []string{"info", "low", "medium", "high", "critical"}
		}
		diagnostics := buildScanDiagnostics(allowedSeverities)

		fmt.Fprintf(logOut, "[SCAN] target=%s severities=%s\n", scanOptions.target, strings.Join(allowedSeverities, ","))
		stopTicker := startScanTicker(logOut, scanOptions.target)

		runOptions := runner.Options{
			TimeoutSeconds:            scanOptions.timeout,
			Retries:                   scanOptions.retries,
			Verbose:                   scanOptions.verbose,
			NoInteractsh:              scanOptions.noInteractsh,
			IncludeHTTP:               scanOptions.includeHTTP,
			EnableHeadless:            scanOptions.enableHeadless,
			EnableDAST:                scanOptions.enableDAST,
			AutomaticScan:             scanOptions.automaticScan,
			IncludeDefaultIgnoredTags: scanOptions.includeDefaultIgnoredTags,
			Headers:                   scanOptions.headers,
			Cookie:                    scanOptions.cookie,
			CookieFile:                scanOptions.cookieFile,
			Tags:                      scanOptions.tags,
			ExcludeTags:               scanOptions.excludeTags,
			Templates:                 scanOptions.templates,
			Workflows:                 scanOptions.workflows,
			Types:                     scanOptions.types,
			ShowCommand:               scanOptions.showNucleiCommand,
			LegacyCompatible:          scanOptions.legacyCompatible,
			LogWriter:                 logOut,
		}

		scanCtx := cmd.Context()
		var cancelScanTimeout func()
		if scanOptions.scanTimeout > 0 {
			scanCtx, cancelScanTimeout = context.WithTimeout(scanCtx, time.Duration(scanOptions.scanTimeout)*time.Second)
			defer cancelScanTimeout()
		}

		scanResult, err := runner.RunNucleiDetailed(scanCtx, scanOptions.target, allowedSeverities, runOptions)
		stopTicker()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		findings := scanResult.Findings

		fmt.Fprintf(logOut, "[FILTER] nuclei output parsed raw=%d filtered=%d severity_skipped=%d malformed=%d\n", scanResult.RawFindings, len(findings), scanResult.FilteredBySeverity, scanResult.MalformedLines)

		if len(findings) == 0 {
			return emitNoFindings(out, scanOptions.target, allowedSeverities, scanOptions.output, time.Since(startedAt), scanResult, diagnostics)
		}

		summary, err := formatFindingsSummary(findings, scanOptions.limit)
		if err != nil {
			return fmt.Errorf("failed to format findings summary: %w", err)
		}

		if len(findings) > scanOptions.limit {
			findings = findings[:scanOptions.limit]
		}

		analysis := ""
		aiUsed := false
		aiStatus := "not_used"
		aiError := ""

		if scanOptions.skipAI {
			fmt.Fprintln(logOut, "[AI] skipped by configuration")
		} else {
			fmt.Fprintf(logOut, "[AI] analyzing %d finding(s)\n", len(findings))

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

			var aiErr error
			analysis, aiErr = ai.SendToLocalAI(cmd.Context(), summary, aiConfig)
			aiUsed = true
			aiStatus = "ok"
			if aiErr != nil {
				fmt.Fprintf(logOut, "[WARN] AI unavailable: %v\n", aiErr)
				analysis = ""
				aiUsed = false
				aiStatus = "unavailable"
				aiError = aiErr.Error()
			}
		}

		validatedReport := validateAndFallbackAIOutput(analysis, findings)
		if aiUsed && strings.TrimSpace(analysis) != "" && strings.TrimSpace(validatedReport) != strings.TrimSpace(analysis) {
			aiStatus = "fallback"
		}

		if scanOptions.output == "json" {
			return emitJSONReport(out, scanOptions.target, allowedSeverities, findings, strings.TrimSpace(validatedReport), aiUsed, aiStatus, aiError, time.Since(startedAt), scanResult, diagnostics)
		}

		fmt.Fprintln(out)
		fmt.Fprintf(out, "Target   : %s\n", scanOptions.target)
		fmt.Fprintf(out, "Findings : %d\n", len(findings))
		fmt.Fprintf(out, "AI Used  : %t\n", aiUsed)
		fmt.Fprintf(out, "AI Status: %s\n", aiStatus)
		fmt.Fprintf(out, "Duration : %s\n", formatDuration(time.Since(startedAt)))
		if aiError != "" {
			fmt.Fprintf(out, "AI Error : %s\n", aiError)
		}
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
	scanCmd.Flags().StringVar(&scanOptions.profile, "profile", "balanced", "Scan profile: fast, balanced, deep, or web-full")
	scanCmd.Flags().StringVar(&scanOptions.severity, "severity", "medium,high,critical", "Severity levels to include")
	scanCmd.Flags().IntVar(&scanOptions.timeout, "timeout", 10, "Timeout in seconds per Nuclei HTTP request")
	scanCmd.Flags().IntVar(&scanOptions.scanTimeout, "scan-timeout", 120, "Maximum duration in seconds for the Nuclei scan phase (0 disables the limit)")
	scanCmd.Flags().IntVar(&scanOptions.retries, "retries", 0, "Number of retries for Nuclei scan")
	scanCmd.Flags().BoolVarP(&scanOptions.verbose, "verbose", "v", false, "Show verbose debug logging on stderr")
	scanCmd.Flags().BoolVar(&scanOptions.noInteractsh, "no-interactsh", true, "Disable out-of-band interaction templates (-ni). Reduces coverage but avoids interactsh dependency")
	scanCmd.Flags().BoolVar(&scanOptions.includeHTTP, "include-http", false, "Include raw HTTP request/response data from Nuclei (-irr). Improves detail but increases scan time and payload size")
	scanCmd.Flags().BoolVar(&scanOptions.includeLowInfo, "include-low-info", false, "Include info and low severity findings in addition to medium/high/critical")
	scanCmd.Flags().BoolVar(&scanOptions.includeOOB, "include-oob", false, "Enable interactsh/OOB templates by clearing --no-interactsh")
	scanCmd.Flags().BoolVar(&scanOptions.enableHeadless, "enable-headless", false, "Enable Nuclei headless browser templates")
	scanCmd.Flags().BoolVar(&scanOptions.enableDAST, "enable-dast", false, "Enable Nuclei DAST/fuzz templates")
	scanCmd.Flags().BoolVar(&scanOptions.automaticScan, "automatic-scan", false, "Enable Nuclei automatic technology-based web scan (-as)")
	scanCmd.Flags().StringSliceVar(&scanOptions.includeDefaultIgnoredTags, "include-default-ignored-tags", nil, "Run tags normally ignored by Nuclei, such as fuzz or bruteforce")
	scanCmd.Flags().BoolVar(&scanOptions.legacyCompatible, "legacy-compatible", false, "Use settings close to the original wrapper behavior")
	scanCmd.Flags().BoolVar(&scanOptions.showNucleiCommand, "show-nuclei-command", false, "Print the final Nuclei command used by the wrapper")
	scanCmd.Flags().StringArrayVar(&scanOptions.headers, "header", nil, "Custom header to include in Nuclei requests, repeatable (Header: value)")
	scanCmd.Flags().StringVar(&scanOptions.cookie, "cookie", "", "Cookie header value to include in Nuclei requests")
	scanCmd.Flags().StringVar(&scanOptions.cookieFile, "cookie-file", "", "File containing headers/cookies to include with Nuclei requests")
	scanCmd.Flags().StringSliceVar(&scanOptions.tags, "tags", nil, "Nuclei template tags to run")
	scanCmd.Flags().StringSliceVar(&scanOptions.excludeTags, "exclude-tags", nil, "Nuclei template tags to exclude")
	scanCmd.Flags().StringSliceVar(&scanOptions.templates, "templates", nil, "Nuclei template files/directories to run")
	scanCmd.Flags().StringSliceVar(&scanOptions.workflows, "workflows", nil, "Nuclei workflow files/directories to run")
	scanCmd.Flags().StringSliceVar(&scanOptions.types, "type", nil, "Nuclei template protocol types to run, such as http,headless,javascript")
	scanCmd.Flags().BoolVar(&scanOptions.skipAI, "skip-ai", false, "Skip AI analysis and return a deterministic fallback report from parsed findings")
	scanCmd.Flags().StringVar(&scanOptions.aiEndpoint, "ai-endpoint", "", "Local AI completion endpoint (overrides environment and config)")
	scanCmd.Flags().StringVar(&scanOptions.aiModel, "ai-model", "", "Local AI model name (overrides environment and config)")
	scanCmd.Flags().StringVar(&scanOptions.aiApiKey, "ai-api-key", "", "API key for AI endpoint (overrides environment and config). Required for cloud endpoints.")
	scanCmd.Flags().IntVar(&scanOptions.aiTimeout, "ai-timeout", 25, "Timeout in seconds for AI completions")
	scanCmd.Flags().IntVar(&scanOptions.limit, "limit", 5, "Maximum number of findings to send to AI for analysis")
	scanCmd.Flags().StringVar(&scanOptions.output, "output", "text", "Output format: text or json")

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

func validateOutputMode(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "text", "json":
		return nil
	default:
		return fmt.Errorf("invalid output mode %q. Supported values: text, json", value)
	}
}

func validateScanProfile(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fast", "balanced", "deep", "web-full":
		return nil
	default:
		return fmt.Errorf("invalid scan profile %q. Supported values: fast, balanced, deep, web-full", value)
	}
}

func applyScanProfile(cmd *cobra.Command) {
	profile := strings.ToLower(strings.TrimSpace(scanOptions.profile))
	if profile == "" {
		profile = "balanced"
	}

	setStringIfUnset := func(flagName, value string, target *string) {
		if !cmd.Flags().Changed(flagName) {
			*target = value
		}
	}
	setIntIfUnset := func(flagName string, value int, target *int) {
		if !cmd.Flags().Changed(flagName) {
			*target = value
		}
	}
	setBoolIfUnset := func(flagName string, value bool, target *bool) {
		if !cmd.Flags().Changed(flagName) {
			*target = value
		}
	}
	setSliceIfUnset := func(flagName string, value []string, target *[]string) {
		if !cmd.Flags().Changed(flagName) {
			*target = value
		}
	}

	if scanOptions.legacyCompatible {
		profile = "deep"
		setBoolIfUnset("include-http", true, &scanOptions.includeHTTP)
	}

	switch profile {
	case "fast":
		setStringIfUnset("severity", "high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 8, &scanOptions.timeout)
		setIntIfUnset("scan-timeout", 60, &scanOptions.scanTimeout)
		setIntIfUnset("retries", 0, &scanOptions.retries)
		setBoolIfUnset("no-interactsh", true, &scanOptions.noInteractsh)
		setBoolIfUnset("skip-ai", true, &scanOptions.skipAI)
		setSliceIfUnset("type", []string{"http"}, &scanOptions.types)
		setIntIfUnset("ai-timeout", 15, &scanOptions.aiTimeout)
		setIntIfUnset("limit", 3, &scanOptions.limit)
	case "deep":
		setStringIfUnset("severity", "medium,high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 30, &scanOptions.timeout)
		setIntIfUnset("scan-timeout", 300, &scanOptions.scanTimeout)
		setIntIfUnset("retries", 2, &scanOptions.retries)
		setBoolIfUnset("no-interactsh", false, &scanOptions.noInteractsh)
		setBoolIfUnset("skip-ai", false, &scanOptions.skipAI)
		setIntIfUnset("ai-timeout", 120, &scanOptions.aiTimeout)
		setIntIfUnset("limit", 10, &scanOptions.limit)
	case "web-full":
		setStringIfUnset("severity", "info,low,medium,high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 30, &scanOptions.timeout)
		setIntIfUnset("scan-timeout", 420, &scanOptions.scanTimeout)
		setIntIfUnset("retries", 1, &scanOptions.retries)
		setBoolIfUnset("no-interactsh", false, &scanOptions.noInteractsh)
		setBoolIfUnset("skip-ai", false, &scanOptions.skipAI)
		setBoolIfUnset("include-http", true, &scanOptions.includeHTTP)
		setBoolIfUnset("enable-headless", true, &scanOptions.enableHeadless)
		setBoolIfUnset("enable-dast", true, &scanOptions.enableDAST)
		setSliceIfUnset("include-default-ignored-tags", []string{"fuzz"}, &scanOptions.includeDefaultIgnoredTags)
		setSliceIfUnset("type", []string{"http", "headless", "javascript"}, &scanOptions.types)
		setIntIfUnset("ai-timeout", 120, &scanOptions.aiTimeout)
		setIntIfUnset("limit", 15, &scanOptions.limit)
	default:
		setStringIfUnset("severity", "medium,high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 10, &scanOptions.timeout)
		setIntIfUnset("scan-timeout", 120, &scanOptions.scanTimeout)
		setIntIfUnset("retries", 0, &scanOptions.retries)
		setBoolIfUnset("no-interactsh", true, &scanOptions.noInteractsh)
		setBoolIfUnset("skip-ai", false, &scanOptions.skipAI)
		setSliceIfUnset("type", []string{"http"}, &scanOptions.types)
		setIntIfUnset("ai-timeout", 25, &scanOptions.aiTimeout)
		setIntIfUnset("limit", 5, &scanOptions.limit)
	}

	if scanOptions.includeOOB {
		scanOptions.noInteractsh = false
	}
	if scanOptions.includeLowInfo {
		scanOptions.severity = "info,low,medium,high,critical"
	}
}

func emitNoFindings(out io.Writer, target string, severities []string, mode string, duration time.Duration, scanResult runner.Result, diagnostics []string) error {
	if mode == "json" {
		return emitJSONReport(out, target, severities, []parser.NucleiFinding{}, "", false, "not_used", "", duration, scanResult, diagnostics)
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "Target   : %s\n", target)
	fmt.Fprintf(out, "Findings : 0\n")
	fmt.Fprintf(out, "Raw      : %d\n", scanResult.RawFindings)
	fmt.Fprintf(out, "Filtered : %d\n", scanResult.FilteredBySeverity)
	fmt.Fprintf(out, "AI Used  : false\n")
	fmt.Fprintf(out, "AI Status: not_used\n")
	fmt.Fprintf(out, "Duration : %s\n", formatDuration(duration))
	fmt.Fprintln(out)
	fmt.Fprintf(out, "[INFO] No findings matched the current scan configuration [%s].\n", strings.Join(severities, ", "))
	for _, reason := range diagnostics {
		fmt.Fprintf(out, "- %s\n", reason)
	}
	fmt.Fprintln(out)
	return nil
}

func emitJSONReport(out io.Writer, target string, severities []string, findings []parser.NucleiFinding, analysis string, aiUsed bool, aiStatus, aiError string, duration time.Duration, scanResult runner.Result, diagnostics []string) error {
	report := scanJSONReport{
		Target:             target,
		Severities:         severities,
		FindingCount:       len(findings),
		RawFindings:        scanResult.RawFindings,
		FilteredFindings:   scanResult.FilteredBySeverity,
		SkippedReasons:     diagnostics,
		Profile:            strings.ToLower(strings.TrimSpace(scanOptions.profile)),
		NucleiCommand:      commandForOutput(scanResult.Command),
		AIUsed:             aiUsed,
		AIStatus:           aiStatus,
		AIError:            strings.TrimSpace(aiError),
		AIAnalysis:         strings.TrimSpace(analysis),
		Findings:           findings,
		DurationSeconds:    int64(duration.Round(time.Second) / time.Second),
		GeneratedAtUnixUTC: time.Now().UTC().Unix(),
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")

	return encoder.Encode(report)
}

func buildScanDiagnostics(severities []string) []string {
	reasons := []string{}
	if !containsSeverity(severities, "info") || !containsSeverity(severities, "low") {
		reasons = append(reasons, "low/info severity findings may be hidden; use --include-low-info for full visibility")
	}
	if scanOptions.noInteractsh {
		reasons = append(reasons, "OOB/interactsh templates are disabled; use --include-oob or --profile web-full")
	}
	if !scanOptions.enableHeadless {
		reasons = append(reasons, "headless browser templates are disabled; use --enable-headless for JavaScript-heavy targets")
	}
	if !scanOptions.enableDAST {
		reasons = append(reasons, "DAST/fuzz templates are disabled; use --enable-dast for parameter fuzzing")
	}
	if len(scanOptions.headers) == 0 && scanOptions.cookie == "" && scanOptions.cookieFile == "" {
		reasons = append(reasons, "scan is unauthenticated; use --header, --cookie, or --cookie-file for login-only apps")
	}
	if len(scanOptions.includeDefaultIgnoredTags) == 0 {
		reasons = append(reasons, "Nuclei default ignored tags such as fuzz/bruteforce remain excluded")
	}
	if scanOptions.scanTimeout > 0 {
		reasons = append(reasons, fmt.Sprintf("Nuclei scan phase is capped at %ds", scanOptions.scanTimeout))
	}
	return reasons
}

func containsSeverity(severities []string, target string) bool {
	for _, severity := range severities {
		if strings.EqualFold(strings.TrimSpace(severity), target) {
			return true
		}
	}
	return false
}

func commandForOutput(command []string) []string {
	if !scanOptions.showNucleiCommand {
		return nil
	}
	return command
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
				fmt.Fprintf(out, "[SCAN] active=%ds target=%s\n", elapsed, target)
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

func formatDuration(duration time.Duration) string {
	if duration < time.Second {
		return "<1s"
	}

	return duration.Round(time.Second).String()
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
			req := trimForAI(finding.Request, 400)
			fmt.Fprintf(&builder, "Request: %s\n", req)
		}

		if finding.Response != "" {
			resp := trimForAI(finding.Response, 400)
			fmt.Fprintf(&builder, "Response: %s\n", resp)
		}

		if builder.Len() >= maxAISummaryChars {
			builder.WriteString("\n... [SUMMARY TRUNCATED FOR AI PAYLOAD LIMIT]\n")
			break
		}
	}

	return trimForAI(builder.String(), maxAISummaryChars), nil
}

func trimForAI(value string, maxChars int) string {
	value = strings.TrimSpace(value)
	if maxChars <= 0 || len(value) <= maxChars {
		return value
	}

	return value[:maxChars] + "\n... [TRUNCATED]"
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
