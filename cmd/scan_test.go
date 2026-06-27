package cmd

import (
	"strings"
	"testing"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
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
