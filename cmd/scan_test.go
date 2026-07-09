package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
	"github.com/Zyrexnn/serahkan-cli/internal/runner"
	"github.com/spf13/cobra"
)

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty target",
			target:  "",
			wantErr: true,
			errMsg:  "target cannot be empty",
		},
		{
			name:    "spaces target",
			target:  "   ",
			wantErr: true,
			errMsg:  "target cannot be empty",
		},
		{
			name:    "invalid scheme ftp",
			target:  "ftp://example.com",
			wantErr: true,
			errMsg:  "invalid target: scheme \"ftp\" is not supported. Target must start with http:// or https://",
		},
		{
			name:    "no scheme",
			target:  "example.com",
			wantErr: true,
			errMsg:  "invalid target: scheme \"\" is not supported. Target must start with http:// or https://",
		},
		{
			name:    "valid http scheme",
			target:  "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid https scheme",
			target:  "https://example.com/some/path?param=1",
			wantErr: false,
		},
		{
			name:    "missing host in http url",
			target:  "http://",
			wantErr: true,
			errMsg:  "invalid target: host/domain name is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateTarget() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
			}
		})
	}
}

func TestParseSeverityFlag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "standard severities",
			input:    "medium,high,critical",
			expected: []string{"medium", "high", "critical"},
		},
		{
			name:     "with spaces and uppercase",
			input:    " Medium , High, CRITICAL ",
			expected: []string{"medium", "high", "critical"},
		},
		{
			name:     "empty input defaults to high/critical",
			input:    "",
			expected: []string{"high", "critical"},
		},
		{
			name:     "only commas",
			input:    ",,,",
			expected: []string{"high", "critical"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSeverityFlag(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected length %d, got %d", len(tt.expected), len(result))
			}
			for i, val := range result {
				if val != tt.expected[i] {
					t.Errorf("expected at index %d to be %q, got %q", i, tt.expected[i], val)
				}
			}
		})
	}
}

func TestValidateOutputMode(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{input: "text", wantErr: false},
		{input: "json", wantErr: false},
		{input: "yaml", wantErr: true},
	}

	for _, tt := range tests {
		err := validateOutputMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateOutputMode(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestValidateScanProfile(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{input: "fast", wantErr: false},
		{input: "balanced", wantErr: false},
		{input: "deep", wantErr: false},
		{input: "web-full", wantErr: false},
		{input: "benchmark-web", wantErr: false},
		{input: "brutal-aggressive", wantErr: false},
		{input: "turbo", wantErr: true},
	}

	for _, tt := range tests {
		err := validateScanProfile(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateScanProfile(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestValidateFocus(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{input: "", wantErr: false},
		{input: "exposures", wantErr: false},
		{input: "web-vulns", wantErr: false},
		{input: "fuzz", wantErr: false},
		{input: "misconfig", wantErr: false},
		{input: "cves", wantErr: false},
		{input: "random", wantErr: true},
	}

	for _, tt := range tests {
		err := validateFocus(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateFocus(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestValidateExportMode(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{input: "", wantErr: false},
		{input: "html", wantErr: false},
		{input: "markdown", wantErr: false},
		{input: "HTML", wantErr: false},
		{input: "MARKDOWN", wantErr: false},
		{input: "pdf", wantErr: true},
		{input: "xml", wantErr: true},
	}

	for _, tt := range tests {
		err := validateExportMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateExportMode(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
	}
}

func makeCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().String("severity", "", "")
	cmd.Flags().String("focus", "", "")
	cmd.Flags().Int("timeout", 0, "")
	cmd.Flags().Int("max-duration", 0, "")
	cmd.Flags().Int("retries", 0, "")
	cmd.Flags().Int("concurrency", 0, "")
	cmd.Flags().Int("rate-limit", 0, "")
	cmd.Flags().Bool("interactsh", false, "")
	cmd.Flags().Bool("raw-http", false, "")
	cmd.Flags().Bool("enable-headless", false, "")
	cmd.Flags().Bool("enable-dast", false, "")
	cmd.Flags().Bool("tech-detect", false, "")
	cmd.Flags().StringSlice("force-tags", nil, "")
	cmd.Flags().StringSlice("protocols", nil, "")
	cmd.Flags().Bool("skip-ai", false, "")
	cmd.Flags().Int("ai-timeout", 0, "")
	cmd.Flags().Int("ai-findings", 0, "")
	return cmd
}

func TestApplyScanProfile(t *testing.T) {

	t.Run("fast profile applies quicker defaults", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "fast"
		scanOptions.severity = "medium,high,critical"

		cmd := makeCommand()
		applyScanProfile(cmd)

		if scanOptions.timeout != 8 || scanOptions.maxDuration != 60 || scanOptions.aiFindings != 3 {
			t.Fatalf("unexpected fast profile values: timeout=%d max-duration=%d ai-findings=%d", scanOptions.timeout, scanOptions.maxDuration, scanOptions.aiFindings)
		}
		if scanOptions.interactsh || !scanOptions.skipAI {
			t.Fatalf("expected fast profile to disable interactsh and skip AI")
		}
		if scanOptions.severity != "high,critical" {
			t.Fatalf("expected fast profile severity override, got %q", scanOptions.severity)
		}
	})

	t.Run("explicit flags override profile defaults", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "deep"
		scanOptions.timeout = 12
		scanOptions.interactsh = false

		cmd := makeCommand()
		if err := cmd.Flags().Set("timeout", "12"); err != nil {
			t.Fatalf("failed to set timeout flag: %v", err)
		}
		if err := cmd.Flags().Set("interactsh", "false"); err != nil {
			t.Fatalf("failed to set interactsh flag: %v", err)
		}

		applyScanProfile(cmd)

		if scanOptions.timeout != 12 {
			t.Fatalf("expected explicit timeout to be preserved, got %d", scanOptions.timeout)
		}
		if scanOptions.interactsh {
			t.Fatalf("expected explicit interactsh=false to be preserved")
		}
		if scanOptions.maxDuration != 300 || scanOptions.aiFindings != 10 {
			t.Fatalf("expected deep profile defaults on unset fields, got max-duration=%d ai-findings=%d", scanOptions.maxDuration, scanOptions.aiFindings)
		}
	})

	t.Run("web-full profile enables coverage options", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "web-full"

		cmd := makeCommand()
		applyScanProfile(cmd)

		if scanOptions.severity != "info,low,medium,high,critical" {
			t.Fatalf("expected web-full severity coverage, got %q", scanOptions.severity)
		}
		if !scanOptions.interactsh || !scanOptions.rawHTTP || !scanOptions.enableHeadless || !scanOptions.enableDAST {
			t.Fatalf("expected web-full to enable OOB, HTTP details, headless, and DAST")
		}
		if scanOptions.techDetect {
			t.Fatalf("expected web-full to leave automatic scan opt-in because Nuclei can fail when no tech tag matches")
		}
		if !containsString(scanOptions.forceTags, "fuzz") {
			t.Fatalf("expected web-full to include fuzz ignored tag")
		}
	})

	t.Run("brutal-aggressive profile enables maximum coverage defaults", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "brutal-aggressive"

		cmd := makeCommand()
		applyScanProfile(cmd)

		if scanOptions.severity != "info,low,medium,high,critical" {
			t.Fatalf("expected brutal-aggressive severity coverage, got %q", scanOptions.severity)
		}
		if scanOptions.timeout != 45 || scanOptions.maxDuration != 600 || scanOptions.retries != 3 {
			t.Fatalf("unexpected brutal-aggressive timing values: timeout=%d max-duration=%d retries=%d", scanOptions.timeout, scanOptions.maxDuration, scanOptions.retries)
		}
		if !scanOptions.interactsh || !scanOptions.rawHTTP || !scanOptions.enableHeadless || !scanOptions.enableDAST || !scanOptions.skipAI {
			t.Fatalf("expected brutal-aggressive to enable OOB, HTTP details, headless, DAST, and skip-ai")
		}
		if !containsString(scanOptions.forceTags, "cve") || !containsString(scanOptions.forceTags, "sqli") || !containsString(scanOptions.forceTags, "xss") || !containsString(scanOptions.forceTags, "lfi") || !containsString(scanOptions.forceTags, "rce") || !containsString(scanOptions.forceTags, "misconfig") || !containsString(scanOptions.forceTags, "exposure") {
			t.Fatalf("expected brutal-aggressive to include cve,sqli,xss,lfi,rce,misconfig,exposure tags")
		}
		if !containsString(scanOptions.protocols, "http") || !containsString(scanOptions.protocols, "dns") {
			t.Fatalf("expected brutal-aggressive to load http/headless/javascript/dns types")
		}
		if !scanOptions.brutalAggressive {
			t.Fatalf("expected brutalAggressive marker to be active")
		}
	})

	t.Run("benchmark-web profile enables benchmark defaults", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "benchmark-web"

		cmd := makeCommand()
		applyScanProfile(cmd)

		if scanOptions.severity != "info,low,medium,high,critical" {
			t.Fatalf("expected benchmark-web severity coverage, got %q", scanOptions.severity)
		}
		if scanOptions.focus != "web-vulns" {
			t.Fatalf("expected benchmark-web focus to default to web-vulns, got %q", scanOptions.focus)
		}
		if scanOptions.interactsh || !scanOptions.rawHTTP || !scanOptions.skipAI {
			t.Fatalf("expected benchmark-web to enable benchmark web scan defaults")
		}
		if scanOptions.enableDAST {
			t.Fatalf("expected benchmark-web to leave DAST disabled for standard HTTP template coverage")
		}
		if !containsString(scanOptions.tags, "xss") || !containsString(scanOptions.tags, "sqli") {
			t.Fatalf("expected benchmark-web to apply web-vulns focus tags")
		}
		if !scanOptions.benchmarkWeb {
			t.Fatalf("expected benchmarkWeb marker to be active")
		}
	})

	t.Run("focus fuzz enables dast and fuzz filters", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "balanced"
		scanOptions.focus = "fuzz"

		cmd := makeCommand()
		applyScanProfile(cmd)

		if !scanOptions.enableDAST {
			t.Fatalf("expected fuzz focus to enable DAST")
		}
		if !containsString(scanOptions.forceTags, "fuzz") || !containsString(scanOptions.tags, "fuzz") {
			t.Fatalf("expected fuzz focus to include fuzz tag controls")
		}
	})
}

func zeroScanOptions() struct {
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
	wafSkip                   bool
	wafStrict                 bool
	loginURL                  string
	loginData                 string
	loginDataFile             string
	loginThreshold            int
	loginCookies              string
} {
	return struct {
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
		wafSkip                   bool
		wafStrict                 bool
		loginURL                  string
		loginData                 string
		loginDataFile             string
		loginThreshold            int
		loginCookies              string
	}{}
}

func TestEmitNoFindingsJSON(t *testing.T) {
	var buf bytes.Buffer

	scanOptions = zeroScanOptions()
	scanOptions.profile = "balanced"
	err := emitNoFindings(&buf, "http://example.com", []string{"high", "critical"}, "json", 3*time.Second, runner.Result{
		RawFindings:        2,
		FilteredBySeverity: 2,
	}, []string{"low/info severity findings may be hidden"}, "http://example.com")
	if err != nil {
		t.Fatalf("emitNoFindings() error = %v", err)
	}

	var report scanJSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to decode json output: %v", err)
	}

	if report.Target != "http://example.com" {
		t.Fatalf("expected target to be encoded, got %q", report.Target)
	}
	if report.FindingCount != 0 {
		t.Fatalf("expected zero findings, got %d", report.FindingCount)
	}
	if report.AIUsed {
		t.Fatalf("expected AIUsed to be false")
	}
	if report.AIStatus != "not_used" {
		t.Fatalf("expected AIStatus=not_used, got %q", report.AIStatus)
	}
	if report.DurationSeconds != 3 {
		t.Fatalf("expected duration_seconds=3, got %d", report.DurationSeconds)
	}
	if report.RawFindings != 2 || report.FilteredFindings != 2 {
		t.Fatalf("expected raw/filter counts in report, got raw=%d filtered=%d", report.RawFindings, report.FilteredFindings)
	}
	if len(report.SkippedReasons) != 1 {
		t.Fatalf("expected skipped reason in report")
	}
	if report.AuthMode != "none" {
		t.Fatalf("expected auth_mode none, got %q", report.AuthMode)
	}
	if report.NucleiExecution == nil {
		t.Fatalf("expected nuclei execution metadata")
	}
}

func TestAuthMode(t *testing.T) {
	scanOptions = zeroScanOptions()
	if got := authMode(); got != "none" {
		t.Fatalf("expected none, got %q", got)
	}

	scanOptions.cookie = "sid=abc"
	if got := authMode(); got != "cookie" {
		t.Fatalf("expected cookie, got %q", got)
	}

	scanOptions.headers = []string{"Authorization: Bearer token"}
	if got := authMode(); got != "mixed" {
		t.Fatalf("expected mixed, got %q", got)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{name: "subsecond", input: 500 * time.Millisecond, expected: "<1s"},
		{name: "seconds", input: 3*time.Second + 200*time.Millisecond, expected: "3s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDuration(tt.input); got != tt.expected {
				t.Fatalf("formatDuration(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestTrimForAI(t *testing.T) {
	value := strings.Repeat("a", 20)
	got := trimForAI(value, 10)
	if !strings.Contains(got, "[TRUNCATED]") {
		t.Fatalf("expected truncated marker, got %q", got)
	}

	short := trimForAI("abc", 10)
	if short != "abc" {
		t.Fatalf("expected unmodified short value, got %q", short)
	}
}

func TestFormatFindingsSummary(t *testing.T) {
	findings := []parser.NucleiFinding{
		{
			TemplateID:  "medium-vuln",
			Name:        "Medium Vulnerability",
			Severity:    "medium",
			MatchedAt:   "http://example.com/1",
			CurlCommand: "curl -v http://example.com/1",
			Request:     "GET /1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			Response:    "HTTP/1.1 200 OK\r\n\r\nBody response here",
		},
		{
			TemplateID: "critical-vuln",
			Name:       "Critical Vulnerability",
			Severity:   "critical",
			MatchedAt:  "http://example.com/2",
			Request:    "GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			Response:   strings.Repeat("R", 1500), // longer than 1000 char limit to test truncation
		},
		{
			TemplateID: "high-vuln",
			Name:       "High Vulnerability",
			Severity:   "high",
			MatchedAt:  "http://example.com/3",
		},
	}

	t.Run("limit and sorting check", func(t *testing.T) {
		// Limit to 2 findings. Due to sorting (critical > high > medium), we should get critical-vuln and high-vuln.
		summary, err := formatFindingsSummary(findings, 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.Contains(summary, "Finding 1\nTemplate ID: critical-vuln") {
			t.Error("expected Finding 1 to be critical-vuln due to sorting")
		}
		if !strings.Contains(summary, "Finding 2\nTemplate ID: high-vuln") {
			t.Error("expected Finding 2 to be high-vuln due to sorting")
		}
		if strings.Contains(summary, "Finding 3") || strings.Contains(summary, "medium-vuln") {
			t.Error("expected finding 3/medium-vuln to be excluded due to limit=2")
		}

		// Truncation check
		if !strings.Contains(summary, "... [TRUNCATED]") {
			t.Error("expected response of critical-vuln to be truncated")
		}
	})

	t.Run("curl command fallback check", func(t *testing.T) {
		// Limit to 3 findings. Since medium-vuln is included and has a curl command, it should be listed.
		// Since high-vuln has no curl command, it should say "Curl Command: Not available"
		summary, err := formatFindingsSummary(findings, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.Contains(summary, "Curl Command: curl -v http://example.com/1") {
			t.Error("expected curl command to be present for medium-vuln")
		}
		if !strings.Contains(summary, "Curl Command: Not available") {
			t.Error("expected fallback message 'Curl Command: Not available' when CurlCommand is empty")
		}
	})

	t.Run("deduplication merges same template-id", func(t *testing.T) {
		dupFindings := []parser.NucleiFinding{
			{TemplateID: "xss", Name: "XSS", Severity: "high", MatchedAt: "http://a.com/1", CurlCommand: "curl http://a.com/1"},
			{TemplateID: "xss", Name: "XSS", Severity: "high", MatchedAt: "http://a.com/2", CurlCommand: "curl http://a.com/2"},
			{TemplateID: "xss", Name: "XSS", Severity: "high", MatchedAt: "http://a.com/3", CurlCommand: "curl http://a.com/3"},
		}

		summary, err := formatFindingsSummary(dupFindings, 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.Contains(summary, "Finding 1\nTemplate ID: xss") {
			t.Error("expected single deduplicated finding")
		}
		if strings.Contains(summary, "Finding 2") {
			t.Error("expected no second finding after deduplication")
		}
		if !strings.Contains(summary, "Affected URLs (3):") {
			t.Error("expected affected URLs count of 3")
		}
		if !strings.Contains(summary, "http://a.com/1") || !strings.Contains(summary, "http://a.com/2") || !strings.Contains(summary, "http://a.com/3") {
			t.Error("expected all 3 affected URLs to be listed")
		}
	})

	t.Run("deduplication keeps different template-ids separate", func(t *testing.T) {
		mixedFindings := []parser.NucleiFinding{
			{TemplateID: "xss", Name: "XSS", Severity: "high", MatchedAt: "http://a.com/1"},
			{TemplateID: "sqli", Name: "SQLi", Severity: "critical", MatchedAt: "http://a.com/2"},
		}

		summary, err := formatFindingsSummary(mixedFindings, 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.Contains(summary, "Template ID: xss") {
			t.Error("expected xss finding")
		}
		if !strings.Contains(summary, "Template ID: sqli") {
			t.Error("expected sqli finding")
		}
	})
}

func TestValidateAndFallbackAIOutput(t *testing.T) {
	findings := []parser.NucleiFinding{
		{
			TemplateID:  "vuln-1",
			Name:        "Test Vuln 1",
			Severity:    "high",
			MatchedAt:   "http://example.com/1",
			Host:        "example.com",
			CurlCommand: "curl http://example.com/1",
			Info: parser.NucleiInfo{
				Description: "vulnerability description",
			},
		},
	}

	t.Run("conforming AI output is unmodified", func(t *testing.T) {
		conformingReport := `
+-------------------------------------------------------------------------+
|                      AI DEFENSIVE ANALYSIS REPORT                       |
+-------------------------------------------------------------------------+

[=] TARGET PROFILE
    - Target Host : example.com
    - Risk Status : HIGH ALERT

[=] ROOT CAUSE ANALYSIS
    Root cause analysis description.

[=] ACTIVE VULNERABILITY AUDIT & MANUAL VALIDATION
===========================================================================
[!] FINDING 1: Test Vuln 1
    - Risk Level  : high
    - Technical Overview: vulnerability description
    - Manual Proof-of-Concept Validation:
      * Execute Command:
        $ curl http://example.com/1

[=] REMEDIATION & HARDENING PLAYBOOK
===========================================================================
[*] ACTION 1: Action 1
    - Targeted Component: Web Server
    - Implementation Code:
      code here
`
		result := validateAndFallbackAIOutput(conformingReport, findings)
		if result != conformingReport {
			t.Errorf("expected conforming report to be returned verbatim, got:\n%s", result)
		}
	})

	t.Run("malformed AI output falls back", func(t *testing.T) {
		malformedReport := "Hey there, this is a response that does not follow the format."
		result := validateAndFallbackAIOutput(malformedReport, findings)

		if !strings.Contains(result, "AI DEFENSIVE ANALYSIS REPORT (FALLBACK)") {
			t.Error("expected fallback header in the report")
		}
		if !strings.Contains(result, "[!] FINDING 1: Test Vuln 1") {
			t.Error("expected finding details in fallback report")
		}
		if !strings.Contains(result, "$ curl http://example.com/1") {
			t.Error("expected validation curl command in fallback report")
		}
		if !strings.Contains(result, "REMEDIATION & HARDENING PLAYBOOK") {
			t.Error("expected playbook section in fallback report")
		}
	})
}

func TestSanitizeTarget(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "clean url unchanged", input: "http://example.com", expected: "http://example.com"},
		{name: "cf_chl_f_tk stripped", input: "http://example.com/?__cf_chl_f_tk=abc123", expected: "http://example.com/"},
		{name: "multiple tracking params stripped", input: "http://example.com/?__cf_chl_f_tk=abc&fbclid=xyz&page=1", expected: "http://example.com/?page=1"},
		{name: "gclid stripped", input: "http://example.com/?gclid=CjwKCA", expected: "http://example.com/"},
		{name: "empty string", input: "", expected: ""},
		{name: "whitespace trimmed", input: "  http://example.com  ", expected: "http://example.com"},
		{name: "valid params preserved", input: "http://example.com/?id=42&name=test", expected: "http://example.com/?id=42&name=test"},
		{name: "challenge token stripped", input: "https://target.com/path?challenge=xyz", expected: "https://target.com/path"},
		{name: "msclkid stripped", input: "http://example.com/?msclkid=abc123", expected: "http://example.com/"},
		{name: "hsenc stripped", input: "http://example.com/?_hsenc=abc", expected: "http://example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeTarget(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestConcurrencyRateLimitOverride(t *testing.T) {
	t.Run("explicit concurrency overrides brutal-aggressive default", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "brutal-aggressive"
		scanOptions.concurrency = 100

		cmd := makeCommand()
		if err := cmd.Flags().Set("concurrency", "100"); err != nil {
			t.Fatalf("failed to set concurrency flag: %v", err)
		}
		applyScanProfile(cmd)

		if scanOptions.concurrency != 100 {
			t.Fatalf("expected explicit concurrency=100 to be preserved, got %d", scanOptions.concurrency)
		}
	})

	t.Run("explicit rate-limit overrides brutal-aggressive default", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "brutal-aggressive"
		scanOptions.rateLimit = 200

		cmd := makeCommand()
		if err := cmd.Flags().Set("rate-limit", "200"); err != nil {
			t.Fatalf("failed to set rate-limit flag: %v", err)
		}
		applyScanProfile(cmd)

		if scanOptions.rateLimit != 200 {
			t.Fatalf("expected explicit rate-limit=200 to be preserved, got %d", scanOptions.rateLimit)
		}
	})

	t.Run("unset concurrency gets zero default", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "balanced"

		cmd := makeCommand()
		applyScanProfile(cmd)

		if scanOptions.concurrency != 0 {
			t.Fatalf("expected unset concurrency to remain 0, got %d", scanOptions.concurrency)
		}
	})
}

func TestWAFBlockedDiagnostics(t *testing.T) {
	diagnostics := buildScanDiagnostics([]string{"high", "critical"}, 3)
	found := false
	for _, reason := range diagnostics {
		if strings.Contains(reason, "3 finding(s) blocked by WAF") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected WAF blocked diagnostic message, got: %v", diagnostics)
	}

	diagnostics = buildScanDiagnostics([]string{"high", "critical"}, 0)
	for _, reason := range diagnostics {
		if strings.Contains(reason, "blocked by WAF") {
			t.Fatalf("expected no WAF diagnostic when wafBlocked=0, got: %v", diagnostics)
		}
	}
}

func TestApplyScanConfigDefaults(t *testing.T) {
	t.Run("config values applied when flags unset", func(t *testing.T) {
		scanOptions = zeroScanOptions()

		cmd := makeCommand()
		applyScanConfigDefaults(cmd)

		if scanOptions.rateLimit != 0 {
			t.Fatalf("expected rate-limit=0 when no config file, got %d", scanOptions.rateLimit)
		}
		if scanOptions.concurrency != 0 {
			t.Fatalf("expected concurrency=0 when no config file, got %d", scanOptions.concurrency)
		}
	})

	t.Run("explicit flags override config defaults", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.rateLimit = 200
		scanOptions.concurrency = 100

		cmd := makeCommand()
		if err := cmd.Flags().Set("rate-limit", "200"); err != nil {
			t.Fatalf("failed to set rate-limit flag: %v", err)
		}
		if err := cmd.Flags().Set("concurrency", "100"); err != nil {
			t.Fatalf("failed to set concurrency flag: %v", err)
		}

		applyScanConfigDefaults(cmd)

		if scanOptions.rateLimit != 200 {
			t.Fatalf("expected explicit rate-limit=200 to be preserved, got %d", scanOptions.rateLimit)
		}
		if scanOptions.concurrency != 100 {
			t.Fatalf("expected explicit concurrency=100 to be preserved, got %d", scanOptions.concurrency)
		}
	})
}
