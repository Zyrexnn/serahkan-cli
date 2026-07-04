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
		{input: "turbo", wantErr: true},
	}

	for _, tt := range tests {
		err := validateScanProfile(tt.input)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateScanProfile(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestApplyScanProfile(t *testing.T) {
	makeCommand := func() *cobra.Command {
		cmd := &cobra.Command{Use: "scan"}
		cmd.Flags().String("severity", "", "")
		cmd.Flags().Int("timeout", 0, "")
		cmd.Flags().Int("scan-timeout", 0, "")
		cmd.Flags().Int("retries", 0, "")
		cmd.Flags().Bool("no-interactsh", false, "")
		cmd.Flags().Bool("include-http", false, "")
		cmd.Flags().Bool("include-low-info", false, "")
		cmd.Flags().Bool("include-oob", false, "")
		cmd.Flags().Bool("enable-headless", false, "")
		cmd.Flags().Bool("enable-dast", false, "")
		cmd.Flags().Bool("automatic-scan", false, "")
		cmd.Flags().StringSlice("include-default-ignored-tags", nil, "")
		cmd.Flags().StringSlice("type", nil, "")
		cmd.Flags().Bool("skip-ai", false, "")
		cmd.Flags().Int("ai-timeout", 0, "")
		cmd.Flags().Int("limit", 0, "")
		return cmd
	}

	t.Run("fast profile applies quicker defaults", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "fast"
		scanOptions.severity = "medium,high,critical"

		cmd := makeCommand()
		applyScanProfile(cmd)

		if scanOptions.timeout != 8 || scanOptions.scanTimeout != 60 || scanOptions.limit != 3 {
			t.Fatalf("unexpected fast profile values: timeout=%d scan-timeout=%d limit=%d", scanOptions.timeout, scanOptions.scanTimeout, scanOptions.limit)
		}
		if !scanOptions.noInteractsh || !scanOptions.skipAI {
			t.Fatalf("expected fast profile to enable no-interactsh and skip-ai")
		}
		if scanOptions.severity != "high,critical" {
			t.Fatalf("expected fast profile severity override, got %q", scanOptions.severity)
		}
	})

	t.Run("explicit flags override profile defaults", func(t *testing.T) {
		scanOptions = zeroScanOptions()
		scanOptions.profile = "deep"
		scanOptions.timeout = 12
		scanOptions.noInteractsh = true

		cmd := makeCommand()
		if err := cmd.Flags().Set("timeout", "12"); err != nil {
			t.Fatalf("failed to set timeout flag: %v", err)
		}
		if err := cmd.Flags().Set("no-interactsh", "true"); err != nil {
			t.Fatalf("failed to set no-interactsh flag: %v", err)
		}

		applyScanProfile(cmd)

		if scanOptions.timeout != 12 {
			t.Fatalf("expected explicit timeout to be preserved, got %d", scanOptions.timeout)
		}
		if !scanOptions.noInteractsh {
			t.Fatalf("expected explicit no-interactsh to be preserved")
		}
		if scanOptions.scanTimeout != 300 || scanOptions.limit != 10 {
			t.Fatalf("expected deep profile defaults on unset fields, got scan-timeout=%d limit=%d", scanOptions.scanTimeout, scanOptions.limit)
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
		if scanOptions.noInteractsh || !scanOptions.includeHTTP || !scanOptions.enableHeadless || !scanOptions.enableDAST {
			t.Fatalf("expected web-full to enable OOB, HTTP details, headless, and DAST")
		}
		if scanOptions.automaticScan {
			t.Fatalf("expected web-full to leave automatic scan opt-in because Nuclei can fail when no tech tag matches")
		}
		if !containsString(scanOptions.includeDefaultIgnoredTags, "fuzz") {
			t.Fatalf("expected web-full to include fuzz ignored tag")
		}
	})
}

func zeroScanOptions() struct {
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
} {
	return struct {
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
	}{}
}

func TestEmitNoFindingsJSON(t *testing.T) {
	var buf bytes.Buffer

	scanOptions = zeroScanOptions()
	scanOptions.profile = "balanced"
	err := emitNoFindings(&buf, "http://example.com", []string{"high", "critical"}, "json", 3*time.Second, runner.Result{
		RawFindings:        2,
		FilteredBySeverity: 2,
	}, []string{"low/info severity findings may be hidden"})
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
