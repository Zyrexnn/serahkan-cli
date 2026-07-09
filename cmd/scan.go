	package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/ai"
	cfgstore "github.com/Zyrexnn/serahkan-cli/internal/config"
	"github.com/Zyrexnn/serahkan-cli/internal/exporter"
	"github.com/Zyrexnn/serahkan-cli/internal/parser"
	"github.com/Zyrexnn/serahkan-cli/internal/runner"
	"github.com/Zyrexnn/serahkan-cli/internal/style"
	"github.com/spf13/cobra"
)

var scanOptions struct {
	target                    string
	targetFile                string
	severity                  string
	profile                   string
	focus                     string
	timeout                   int
	maxDuration               int
	retries                   int
	concurrency               int
	rateLimit                 int
	verbose                   bool
	interactsh                bool
	rawHTTP                   bool
	enableHeadless            bool
	enableDAST                bool
	techDetect                bool
	forceTags                 []string
	brutalAggressive          bool
	benchmarkWeb              bool
	showNucleiCommand         bool
	headers                   []string
	cookie                    string
	cookieFile                string
	tags                      []string
	excludeTags               []string
	templates                 []string
	workflows                 []string
	protocols                 []string
	skipAI                    bool
	aiEndpoint                string
	aiModel                   string
	aiApiKey                  string
	aiTimeout                 int
	aiFindings                int
	output                    string
	export                    string
	crawl                     bool
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
	WAFBlocked         int                    `json:"waf_blocked"`
	SkippedReasons     []string               `json:"skipped_reasons,omitempty"`
	Profile            string                 `json:"profile"`
	Focus              string                 `json:"focus,omitempty"`
	AuthMode           string                 `json:"auth_mode"`
	NucleiExecution    map[string]interface{} `json:"nuclei_execution,omitempty"`
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

	var exportBuf *strings.Builder
	var actualOut io.Writer = out
	if scanOptions.export != "" {
		exportBuf = &strings.Builder{}
		actualOut = out
	}

		applyScanConfigDefaults(cmd)
		applyScanProfile(cmd)

		scanOptions.targetFile = strings.TrimSpace(scanOptions.targetFile)

		if scanOptions.targetFile != "" {
			if _, err := os.Stat(scanOptions.targetFile); err != nil {
				return fmt.Errorf("target file not found or not readable: %s", scanOptions.targetFile)
			}
		}

		if scanOptions.target == "" && scanOptions.targetFile == "" {
			return fmt.Errorf("either --target or --target-file is required")
		}

		if scanOptions.targetFile != "" && scanOptions.target != "" {
			return fmt.Errorf("--target and --target-file cannot be used together")
		}

		scanOptions.target = sanitizeTarget(scanOptions.target)

		if cmd.Flags().Changed("ai-endpoint") {
			scanOptions.skipAI = false
		}

		if cmd.Flags().Changed("skip-ai") {
			if scanOptions.skipAI {
				scanOptions.aiEndpoint = ""
				scanOptions.aiModel = ""
			}
		}

		if scanOptions.target != "" {
			if err := validateTarget(scanOptions.target); err != nil {
				return err
			}
		}
		if err := validateOutputMode(scanOptions.output); err != nil {
			return err
		}
		if err := validateScanProfile(scanOptions.profile); err != nil {
			return err
		}
		if err := validateFocus(scanOptions.focus); err != nil {
			return err
		}
		if err := validateExportMode(scanOptions.export); err != nil {
			return err
		}

		allowedSeverities := parseSeverityFlag(scanOptions.severity)
		if cmd.Flags().Changed("ai-endpoint") {
			allowedSeverities = []string{"info", "low", "medium", "high", "critical"}
		}
		diagnostics := buildScanDiagnostics(allowedSeverities, 0)

		targetLabel := scanOptions.target
		if targetLabel == "" {
			targetLabel = "file:" + scanOptions.targetFile
		}
		fmt.Fprintf(logOut, "%s target=%s severities=%s\n", style.TagScan, style.Target(targetLabel), style.Metric(strings.Join(allowedSeverities, ",")))
		stopTicker := startScanTicker(logOut, targetLabel)

		runOptions := runner.Options{
			TimeoutSeconds:            scanOptions.timeout,
			Retries:                   scanOptions.retries,
			Verbose:                   scanOptions.verbose,
			NoInteractsh:              !scanOptions.interactsh,
			Concurrency:               scanOptions.concurrency,
			RateLimit:                 scanOptions.rateLimit,
			RawHTTP:                   scanOptions.rawHTTP,
			EnableHeadless:            scanOptions.enableHeadless,
			EnableDAST:                scanOptions.enableDAST,
			TechDetect:                scanOptions.techDetect,
			ForceTags:                 scanOptions.forceTags,
			Headers:                   scanOptions.headers,
			Cookie:                    scanOptions.cookie,
			CookieFile:                scanOptions.cookieFile,
			Tags:                      scanOptions.tags,
			ExcludeTags:               scanOptions.excludeTags,
			Templates:                 scanOptions.templates,
			Workflows:                 scanOptions.workflows,
			Protocols:                 scanOptions.protocols,
			ShowCommand:               scanOptions.showNucleiCommand,
			LogWriter:                 logOut,
			EnableCrawl:               scanOptions.crawl,
			TargetsFile:               scanOptions.targetFile,
		}
		if scanOptions.brutalAggressive {
			if scanOptions.concurrency == 0 {
				runOptions.Concurrency = 300
			}
			if scanOptions.rateLimit == 0 {
				runOptions.RateLimit = 800
			}
		}

		scanCtx := cmd.Context()
		var cancelScanTimeout func()
		if scanOptions.maxDuration > 0 {
			scanCtx, cancelScanTimeout = context.WithTimeout(scanCtx, time.Duration(scanOptions.maxDuration)*time.Second)
			defer cancelScanTimeout()
		}

		scanResult, err := runner.RunNucleiScan(scanCtx, scanOptions.target, allowedSeverities, runOptions)
		stopTicker()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		findings := scanResult.Findings

		if scanResult.WAFBlocked > 0 {
			diagnostics = buildScanDiagnostics(allowedSeverities, scanResult.WAFBlocked)
		}

		fmt.Fprintf(logOut, "%s raw=%s filtered=%s severity_skipped=%s waf_blocked=%s malformed=%s\n", style.TagFilter, style.Metric(fmt.Sprintf("%d", scanResult.RawFindings)), style.Metric(fmt.Sprintf("%d", len(findings))), style.Metric(fmt.Sprintf("%d", scanResult.FilteredBySeverity)), style.Metric(fmt.Sprintf("%d", scanResult.WAFBlocked)), style.Metric(fmt.Sprintf("%d", scanResult.MalformedLines)))

		if len(findings) == 0 {
			if exportBuf != nil {
				fmt.Fprintf(exportBuf, "Target: %s\n", targetLabel)
				fmt.Fprintf(exportBuf, "Severities: %s\n", strings.Join(allowedSeverities, ", "))
				fmt.Fprintf(exportBuf, "Findings: 0\n")
				fmt.Fprintf(exportBuf, "Duration: %s\n", formatDuration(time.Since(startedAt)))
				for _, reason := range diagnostics {
					fmt.Fprintf(exportBuf, "  - %s\n", reason)
				}
			}
			return emitNoFindings(out, targetLabel, allowedSeverities, scanOptions.output, time.Since(startedAt), scanResult, diagnostics)
		}

		summary, err := formatFindingsSummary(findings, scanOptions.aiFindings)
		if err != nil {
			return fmt.Errorf("failed to format findings summary: %w", err)
		}

		if len(findings) > scanOptions.aiFindings {
			findings = findings[:scanOptions.aiFindings]
		}

		if exportBuf != nil {
			fmt.Fprintf(exportBuf, "Filtered Nuclei findings requiring defensive analysis:\n")
			for i, f := range findings {
				fmt.Fprintf(exportBuf, "\nFinding %d\n", i+1)
				fmt.Fprintf(exportBuf, "Template ID: %s\n", f.TemplateID)
				fmt.Fprintf(exportBuf, "Name: %s\n", f.Name)
				fmt.Fprintf(exportBuf, "Severity: %s\n", f.Severity)
				fmt.Fprintf(exportBuf, "Matched At: %s\n", f.MatchedAt)
				if f.Host != "" {
					fmt.Fprintf(exportBuf, "Host: %s\n", f.Host)
				}
				if f.Info.Description != "" {
					fmt.Fprintf(exportBuf, "Description: %s\n", f.Info.Description)
				}
				if f.CurlCommand != "" {
					fmt.Fprintf(exportBuf, "Curl Command: %s\n", f.CurlCommand)
				}
			}
		}

		analysis := ""
		aiUsed := false
		aiStatus := "not_used"
		aiError := ""
		streamed := false

		if scanOptions.skipAI {
			fmt.Fprintf(logOut, "%s skipped by configuration\n", style.TagAI)
		} else {
			fmt.Fprintf(logOut, "%s analyzing %s finding(s)\n", style.TagAI, style.Bold(fmt.Sprintf("%d", len(findings))))

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

			if scanOptions.output == "json" {
				var aiErr error
				analysis, aiErr = ai.SendToLocalAI(cmd.Context(), summary, aiConfig)
				aiUsed = true
				aiStatus = "ok"
				if aiErr != nil {
					fmt.Fprintf(logOut, "%s AI unavailable: %v\n", style.TagWarn, aiErr)
					aiStatus = "unavailable"
					aiError = aiErr.Error()
				}
				if exportBuf != nil && analysis != "" {
					fmt.Fprintln(exportBuf)
					fmt.Fprintln(exportBuf, analysis)
				}
			} else {
				streamed = true
				if exportBuf != nil {
					fmt.Fprintln(exportBuf)
				}
				style.PrintAIReportHeader(actualOut)
				var lineBuf strings.Builder
				var aiErr error
				analysis, aiErr = ai.StreamToLocalAI(cmd.Context(), summary, aiConfig, func(token string) {
					lineBuf.WriteString(token)
					for {
						raw := lineBuf.String()
						idx := strings.Index(raw, "\n")
						if idx < 0 {
							break
						}
						line := raw[:idx]
						lineBuf.Reset()
						lineBuf.WriteString(raw[idx+1:])
						style.PrintAIReportLine(actualOut, line)
						if exportBuf != nil {
							fmt.Fprintln(exportBuf, line)
						}
					}
				})
				remaining := strings.TrimSpace(lineBuf.String())
				if remaining != "" {
					style.PrintAIReportLine(actualOut, remaining)
					if exportBuf != nil {
						fmt.Fprintln(exportBuf, remaining)
					}
				}
				style.PrintAIReportFooter(actualOut)
				aiUsed = true
				aiStatus = "ok"
				if aiErr != nil {
					fmt.Fprintf(logOut, "%s AI unavailable: %v\n", style.TagWarn, aiErr)
					aiStatus = "unavailable"
					aiError = aiErr.Error()
				}
			}
		}

		validatedReport := validateAndFallbackAIOutput(analysis, findings)
		if aiError != "" && len(findings) > 0 {
			aiStatus = "fallback"
		} else if aiUsed && strings.TrimSpace(analysis) != "" && strings.TrimSpace(validatedReport) != strings.TrimSpace(analysis) {
			aiStatus = "fallback"
		}

		if scanOptions.output == "json" {
			return emitJSONReport(out, targetLabel, allowedSeverities, findings, strings.TrimSpace(validatedReport), aiUsed, aiStatus, aiError, time.Since(startedAt), scanResult, diagnostics)
		}

		style.PrintScanSummary(actualOut, targetLabel, len(findings), aiUsed, aiStatus, formatDuration(time.Since(startedAt)))
		if aiError != "" {
			fmt.Fprintf(actualOut, "  %s  %s\n", style.Yellow.Sprint("AI Error:"), style.Warn(aiError))
		}
		if !streamed {
			style.PrintAIReport(actualOut, strings.TrimSpace(validatedReport))
		}

		if scanOptions.export != "" && exportBuf != nil {
			reportData := exporter.ReportData{
				Target:       targetLabel,
				Findings:     strings.TrimSpace(validatedReport),
				AISummary:    exportBuf.String(),
				ScanDuration: formatDuration(time.Since(startedAt)),
				Timestamp:    time.Now(),
				FindingCount: len(findings),
				AIUsed:       aiUsed,
				AIStatus:     aiStatus,
				Version:      Version,
			}

			var savedPath string
			var exportErr error
			switch strings.ToLower(scanOptions.export) {
			case "html":
				savedPath, exportErr = exporter.ExportHTML(reportData)
			case "markdown":
				savedPath, exportErr = exporter.ExportMarkdown(reportData)
			}

			if exportErr != nil {
				fmt.Fprintf(logOut, "%s export failed: %v\n", style.TagWarn, exportErr)
			} else {
				fmt.Fprintf(logOut, "%s report saved to %s\n", style.TagOK, style.Target(savedPath))
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOptions.target, "target", "t", "", "Target URL to scan (e.g. http://example.com)")
	scanCmd.Flags().StringVarP(&scanOptions.targetFile, "target-file", "T", "", "File containing list of target URLs to scan (one per line)")
	scanCmd.Flags().StringVar(&scanOptions.profile, "profile", "balanced", "Scan profile: fast, balanced, deep, web-full, benchmark-web, or brutal-aggressive")
	scanCmd.Flags().StringVar(&scanOptions.focus, "focus", "", "Template focus preset: exposures, web-vulns, fuzz, misconfig, or cves")
	scanCmd.Flags().StringVar(&scanOptions.severity, "severity", "medium,high,critical", "Severity levels to include")
	scanCmd.Flags().IntVar(&scanOptions.timeout, "timeout", 10, "Timeout in seconds per Nuclei HTTP request")
	scanCmd.Flags().IntVar(&scanOptions.maxDuration, "max-duration", 120, "Maximum duration in seconds for the Nuclei scan phase (0 disables the limit)")
	scanCmd.Flags().IntVar(&scanOptions.retries, "retries", 0, "Number of retries for Nuclei scan")
	scanCmd.Flags().IntVar(&scanOptions.concurrency, "concurrency", 0, "Nuclei connection concurrency (overrides profile defaults when explicitly set)")
	scanCmd.Flags().IntVar(&scanOptions.rateLimit, "rate-limit", 0, "Nuclei requests per second rate limit (overrides profile defaults when explicitly set)")
	scanCmd.Flags().BoolVarP(&scanOptions.verbose, "verbose", "v", false, "Show verbose debug logging on stderr")
	scanCmd.Flags().BoolVar(&scanOptions.interactsh, "interactsh", false, "Enable out-of-band interaction templates")
	scanCmd.Flags().BoolVar(&scanOptions.rawHTTP, "raw-http", false, "Include raw HTTP request/response data from Nuclei (-irr)")
	scanCmd.Flags().BoolVar(&scanOptions.enableHeadless, "enable-headless", false, "Enable Nuclei headless browser templates")
	scanCmd.Flags().BoolVar(&scanOptions.enableDAST, "enable-dast", false, "Enable Nuclei DAST/fuzz templates")
	scanCmd.Flags().BoolVar(&scanOptions.techDetect, "tech-detect", false, "Enable Nuclei automatic technology detection (-as)")
	scanCmd.Flags().StringSliceVar(&scanOptions.forceTags, "force-tags", nil, "Run tags normally ignored by Nuclei, such as fuzz or bruteforce")
	scanCmd.Flags().BoolVar(&scanOptions.showNucleiCommand, "show-nuclei-command", false, "Print the final Nuclei command used by the wrapper")
	scanCmd.Flags().StringArrayVar(&scanOptions.headers, "header", nil, "Custom header to include in Nuclei requests, repeatable (Header: value)")
	scanCmd.Flags().StringVar(&scanOptions.cookie, "cookie", "", "Cookie header value to include in Nuclei requests")
	scanCmd.Flags().StringVar(&scanOptions.cookieFile, "cookie-file", "", "File containing headers/cookies to include with Nuclei requests")
	scanCmd.Flags().StringSliceVar(&scanOptions.tags, "tags", nil, "Nuclei template tags to run")
	scanCmd.Flags().StringSliceVar(&scanOptions.excludeTags, "exclude-tags", nil, "Nuclei template tags to exclude")
	scanCmd.Flags().StringSliceVar(&scanOptions.templates, "templates", nil, "Nuclei template files/directories to run")
	scanCmd.Flags().StringSliceVar(&scanOptions.workflows, "workflows", nil, "Nuclei workflow files/directories to run")
	scanCmd.Flags().StringSliceVar(&scanOptions.protocols, "protocols", nil, "Nuclei template protocols to run, such as http,headless,javascript")
	scanCmd.Flags().BoolVar(&scanOptions.skipAI, "skip-ai", false, "Skip AI analysis and return a deterministic fallback report from parsed findings")
	scanCmd.Flags().StringVar(&scanOptions.aiEndpoint, "ai-endpoint", "", "Local AI completion endpoint (overrides environment and config)")
	scanCmd.Flags().StringVar(&scanOptions.aiModel, "ai-model", "", "Local AI model name (overrides environment and config)")
	scanCmd.Flags().StringVar(&scanOptions.aiApiKey, "ai-api-key", "", "API key for AI endpoint (overrides environment and config). Required for cloud endpoints.")
	scanCmd.Flags().IntVar(&scanOptions.aiTimeout, "ai-timeout", 25, "Timeout in seconds for AI completions")
	scanCmd.Flags().IntVar(&scanOptions.aiFindings, "ai-findings", 5, "Maximum number of findings to send to AI for analysis")
	scanCmd.Flags().StringVar(&scanOptions.output, "output", "text", "Output format: text or json")
	scanCmd.Flags().StringVar(&scanOptions.export, "export", "", "Export report to file: html or markdown")
	scanCmd.Flags().BoolVar(&scanOptions.crawl, "crawl", false, "Enable Katana crawler to discover additional sub-pages before scanning")

	advancedFlags := []string{
		"concurrency",
		"rate-limit",
		"raw-http",
		"enable-headless",
		"enable-dast",
		"tech-detect",
		"force-tags",
		"header",
		"cookie",
		"cookie-file",
		"tags",
		"exclude-tags",
		"templates",
		"workflows",
		"protocols",
	}
	for _, flag := range advancedFlags {
		_ = scanCmd.Flags().MarkHidden(flag)
	}
}

func sanitizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	changed := false
	for key := range q {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "cf_chl") || strings.Contains(lower, "challenge") || strings.Contains(lower, "__cf") || strings.Contains(lower, "fbclid") || strings.Contains(lower, "gclid") || strings.Contains(lower, "mc_eid") || strings.Contains(lower, "msclkid") || strings.Contains(lower, "trk") || strings.Contains(lower, "oly_enc_id") || strings.Contains(lower, "_hsenc") || strings.Contains(lower, "_hsm") || strings.Contains(lower, "ss_compile") || strings.Contains(lower, "vero_id") {
			q.Del(key)
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
		return u.String()
	}
	return raw
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
	case "fast", "balanced", "deep", "web-full", "benchmark-web", "brutal-aggressive":
		return nil
	default:
		return fmt.Errorf("invalid scan profile %q. Supported values: fast, balanced, deep, web-full, benchmark-web, brutal-aggressive", value)
	}
}

func validateFocus(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "exposures", "web-vulns", "fuzz", "misconfig", "cves":
		return nil
	default:
		return fmt.Errorf("invalid focus %q. Supported values: exposures, web-vulns, fuzz, misconfig, cves", value)
	}
}

func validateExportMode(value string) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "html", "markdown":
		return nil
	default:
		return fmt.Errorf("invalid export mode %q. Supported values: html, markdown", value)
	}
}

func applyScanConfigDefaults(cmd *cobra.Command) {
	scanCfg := cfgstore.LoadScanConfig()

	setIfUnset := func(flagName string, value int, target *int) {
		if !cmd.Flags().Changed(flagName) && *target == 0 && value > 0 {
			*target = value
		}
	}

	setIfUnset("rate-limit", scanCfg.RateLimit, &scanOptions.rateLimit)
	setIfUnset("concurrency", scanCfg.Concurrency, &scanOptions.concurrency)

	if !cmd.Flags().Changed("ai-endpoint") && scanCfg.AIEndpoint != "" {
		scanOptions.aiEndpoint = scanCfg.AIEndpoint
	}
	if !cmd.Flags().Changed("ai-model") && scanCfg.AIModel != "" {
		scanOptions.aiModel = scanCfg.AIModel
	}

	if scanCfg.AIEndpoint != "" && scanCfg.AIModel != "" && !cmd.Flags().Changed("skip-ai") {
		scanOptions.skipAI = false
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

	scanOptions.brutalAggressive = false
	scanOptions.benchmarkWeb = false

	switch profile {
	case "fast":
		setStringIfUnset("severity", "high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 8, &scanOptions.timeout)
		setIntIfUnset("max-duration", 60, &scanOptions.maxDuration)
		setIntIfUnset("retries", 0, &scanOptions.retries)
		setBoolIfUnset("skip-ai", true, &scanOptions.skipAI)
		setSliceIfUnset("protocols", []string{"http"}, &scanOptions.protocols)
		setIntIfUnset("ai-timeout", 15, &scanOptions.aiTimeout)
		setIntIfUnset("ai-findings", 3, &scanOptions.aiFindings)
	case "deep":
		setStringIfUnset("severity", "medium,high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 30, &scanOptions.timeout)
		setIntIfUnset("max-duration", 300, &scanOptions.maxDuration)
		setIntIfUnset("retries", 2, &scanOptions.retries)
		setBoolIfUnset("interactsh", true, &scanOptions.interactsh)
		setBoolIfUnset("skip-ai", false, &scanOptions.skipAI)
		setIntIfUnset("ai-timeout", 120, &scanOptions.aiTimeout)
		setIntIfUnset("ai-findings", 10, &scanOptions.aiFindings)
	case "web-full":
		setStringIfUnset("severity", "info,low,medium,high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 30, &scanOptions.timeout)
		setIntIfUnset("max-duration", 420, &scanOptions.maxDuration)
		setIntIfUnset("retries", 1, &scanOptions.retries)
		setBoolIfUnset("interactsh", true, &scanOptions.interactsh)
		setBoolIfUnset("skip-ai", false, &scanOptions.skipAI)
		setBoolIfUnset("raw-http", true, &scanOptions.rawHTTP)
		setBoolIfUnset("enable-headless", true, &scanOptions.enableHeadless)
		setBoolIfUnset("enable-dast", true, &scanOptions.enableDAST)
		setSliceIfUnset("force-tags", []string{"fuzz"}, &scanOptions.forceTags)
		setSliceIfUnset("protocols", []string{"http", "headless", "javascript"}, &scanOptions.protocols)
		setIntIfUnset("ai-timeout", 120, &scanOptions.aiTimeout)
		setIntIfUnset("ai-findings", 15, &scanOptions.aiFindings)
	case "benchmark-web":
		scanOptions.benchmarkWeb = true
		setStringIfUnset("severity", "info,low,medium,high,critical", &scanOptions.severity)
		setStringIfUnset("focus", "web-vulns", &scanOptions.focus)
		setIntIfUnset("timeout", 25, &scanOptions.timeout)
		setIntIfUnset("max-duration", 300, &scanOptions.maxDuration)
		setIntIfUnset("retries", 3, &scanOptions.retries)
		setBoolIfUnset("skip-ai", true, &scanOptions.skipAI)
		setBoolIfUnset("raw-http", true, &scanOptions.rawHTTP)
		setBoolIfUnset("enable-dast", false, &scanOptions.enableDAST)
		setSliceIfUnset("protocols", []string{"http"}, &scanOptions.protocols)
		setIntIfUnset("ai-findings", 20, &scanOptions.aiFindings)
	case "brutal-aggressive":
		scanOptions.brutalAggressive = true
		setStringIfUnset("severity", "info,low,medium,high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 45, &scanOptions.timeout)
		setIntIfUnset("max-duration", 600, &scanOptions.maxDuration)
		setIntIfUnset("retries", 3, &scanOptions.retries)
		setBoolIfUnset("interactsh", true, &scanOptions.interactsh)
		setBoolIfUnset("skip-ai", true, &scanOptions.skipAI)
		setBoolIfUnset("raw-http", true, &scanOptions.rawHTTP)
		setBoolIfUnset("enable-headless", true, &scanOptions.enableHeadless)
		setBoolIfUnset("enable-dast", true, &scanOptions.enableDAST)
		setSliceIfUnset("force-tags", []string{"cve", "sqli", "xss", "lfi", "rce", "misconfig", "exposure"}, &scanOptions.forceTags)
		setSliceIfUnset("protocols", []string{"http", "headless", "javascript", "dns"}, &scanOptions.protocols)
		setIntIfUnset("ai-findings", 25, &scanOptions.aiFindings)
	default:
		setStringIfUnset("severity", "medium,high,critical", &scanOptions.severity)
		setIntIfUnset("timeout", 10, &scanOptions.timeout)
		setIntIfUnset("max-duration", 120, &scanOptions.maxDuration)
		setIntIfUnset("retries", 0, &scanOptions.retries)
		setBoolIfUnset("skip-ai", false, &scanOptions.skipAI)
		setSliceIfUnset("protocols", []string{"http"}, &scanOptions.protocols)
		setIntIfUnset("ai-timeout", 25, &scanOptions.aiTimeout)
		setIntIfUnset("ai-findings", 5, &scanOptions.aiFindings)
	}
	applyFocusPreset(cmd)
}

func applyFocusPreset(cmd *cobra.Command) {
	switch strings.ToLower(strings.TrimSpace(scanOptions.focus)) {
	case "exposures":
		appendSliceIfUnset(cmd, "templates", []string{"http/exposures"}, &scanOptions.templates)
	case "web-vulns":
		appendSliceIfUnset(cmd, "tags", []string{"xss", "sqli", "lfi", "rfi", "ssrf", "ssti", "redirect"}, &scanOptions.tags)
	case "fuzz":
		if !cmd.Flags().Changed("enable-dast") {
			scanOptions.enableDAST = true
		}
		appendSliceIfUnset(cmd, "force-tags", []string{"fuzz"}, &scanOptions.forceTags)
		appendSliceIfUnset(cmd, "tags", []string{"fuzz"}, &scanOptions.tags)
	case "misconfig":
		appendSliceIfUnset(cmd, "tags", []string{"misconfig", "exposure", "config"}, &scanOptions.tags)
	case "cves":
		appendSliceIfUnset(cmd, "templates", []string{"http/cves"}, &scanOptions.templates)
	}
}

func appendSliceIfUnset(cmd *cobra.Command, flagName string, values []string, target *[]string) {
	if cmd.Flags().Changed(flagName) {
		return
	}
	existing := map[string]struct{}{}
	for _, value := range *target {
		existing[value] = struct{}{}
	}
	for _, value := range values {
		if _, ok := existing[value]; !ok {
			*target = append(*target, value)
		}
	}
}

func emitNoFindings(out io.Writer, target string, severities []string, mode string, duration time.Duration, scanResult runner.Result, diagnostics []string) error {
	if mode == "json" {
		return emitJSONReport(out, target, severities, []parser.NucleiFinding{}, "", false, "not_used", "", duration, scanResult, diagnostics)
	}

	style.PrintNoFindingsSummary(out, target, scanResult.RawFindings, scanResult.FilteredBySeverity, formatDuration(duration))
	fmt.Fprintf(out, "  %s %s [%s]\n", style.TagInfo, style.Dim("No findings matched the current scan configuration"), style.Dim(strings.Join(severities, ", ")))
	for _, reason := range diagnostics {
		fmt.Fprintf(out, "  %s %s\n", style.DimWhite.Sprint("-"), style.Dim(reason))
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
		WAFBlocked:         scanResult.WAFBlocked,
		SkippedReasons:     diagnostics,
		Profile:            strings.ToLower(strings.TrimSpace(scanOptions.profile)),
		Focus:              strings.ToLower(strings.TrimSpace(scanOptions.focus)),
		AuthMode:           authMode(),
		NucleiExecution:    nucleiExecution(scanResult),
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

func buildScanDiagnostics(severities []string, wafBlocked int) []string {
	reasons := []string{}
	if !containsSeverity(severities, "info") || !containsSeverity(severities, "low") {
		reasons = append(reasons, "low/info severity findings may be hidden; use --severity info,low,medium,high,critical for full visibility")
	}
	if !scanOptions.interactsh {
		reasons = append(reasons, "OOB/interactsh templates are disabled; use --interactsh or --profile web-full")
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
	if len(scanOptions.forceTags) == 0 {
		reasons = append(reasons, "Nuclei default ignored tags such as fuzz/bruteforce remain excluded")
	}
	if scanOptions.brutalAggressive {
		reasons = append(reasons, "coverage-heavy mode is active with elevated timeout, concurrency, rate-limit, DAST, headless, and OOB scanning")
	}
	if scanOptions.benchmarkWeb {
		reasons = append(reasons, "benchmark-web mode is active for public vulnerable demo targets and web vulnerability templates")
	}
	if focus := strings.TrimSpace(scanOptions.focus); focus != "" {
		reasons = append(reasons, fmt.Sprintf("focus preset %q is active", focus))
	}
	if scanOptions.maxDuration > 0 {
		reasons = append(reasons, fmt.Sprintf("Nuclei scan phase is capped at %ds", scanOptions.maxDuration))
	}
	if wafBlocked > 0 {
		reasons = append(reasons, fmt.Sprintf("%d finding(s) blocked by WAF/security filter and excluded from results", wafBlocked))
	}
	return reasons
}

func authMode() string {
	hasHeader := len(scanOptions.headers) > 0
	hasCookie := strings.TrimSpace(scanOptions.cookie) != ""
	hasCookieFile := strings.TrimSpace(scanOptions.cookieFile) != ""
	count := 0
	for _, enabled := range []bool{hasHeader, hasCookie, hasCookieFile} {
		if enabled {
			count++
		}
	}
	if count > 1 {
		return "mixed"
	}
	if hasHeader {
		return "header"
	}
	if hasCookie {
		return "cookie"
	}
	if hasCookieFile {
		return "cookie_file"
	}
	return "none"
}

func nucleiExecution(scanResult runner.Result) map[string]interface{} {
	execution := map[string]interface{}{
		"tech_detect":                  scanOptions.techDetect,
		"raw_http":                     scanOptions.rawHTTP,
		"headless":                     scanOptions.enableHeadless,
		"dast":                         scanOptions.enableDAST,
		"oob":                          scanOptions.interactsh,
		"protocols":                    scanOptions.protocols,
		"tags":                         scanOptions.tags,
		"exclude_tags":                 scanOptions.excludeTags,
		"templates":                    scanOptions.templates,
		"workflows":                    scanOptions.workflows,
		"force_tags":                   scanOptions.forceTags,
		"concurrency":                  scanOptions.concurrency,
		"rate_limit":                   scanOptions.rateLimit,
		"total_lines":                  scanResult.TotalLines,
		"malformed_lines":              scanResult.MalformedLines,
		"waf_blocked":                  scanResult.WAFBlocked,
	}
	if scanResult.Stderr != "" {
		execution["stderr"] = scanResult.Stderr
	}
	return execution
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
				fmt.Fprintf(out, "%s active=%s target=%s\n", style.TagScan, style.Metric(fmt.Sprintf("%ds", elapsed)), style.Target(target))
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
	if maxFindings <= 0 {
		maxFindings = 5
	}
	var builder strings.Builder
	builder.WriteString("Filtered Nuclei findings requiring defensive analysis:\n")

	deduplicated := parser.DeduplicateFindings(findings)

	sort.Slice(deduplicated, func(i, j int) bool {
		return severityRank[strings.ToLower(deduplicated[i].Representative.Severity)] > severityRank[strings.ToLower(deduplicated[j].Representative.Severity)]
	})

	displayCount := len(deduplicated)
	if displayCount > maxFindings {
		displayCount = maxFindings
	}

	for i := 0; i < displayCount; i++ {
		dup := deduplicated[i]
		finding := dup.Representative
		fmt.Fprintf(&builder, "\nFinding %d\n", i+1)
		fmt.Fprintf(&builder, "Template ID: %s\n", finding.TemplateID)
		fmt.Fprintf(&builder, "Name: %s\n", finding.Name)
		fmt.Fprintf(&builder, "Severity: %s\n", finding.Severity)
		fmt.Fprintf(&builder, "Affected URLs (%d):\n", len(dup.AffectedURLs))
		for _, url := range dup.AffectedURLs {
			fmt.Fprintf(&builder, "  - %s\n", url)
		}

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
