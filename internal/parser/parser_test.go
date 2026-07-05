package parser

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestParseAndFilterReader(t *testing.T) {
	inputJSONL := `{"template-id":"xss","name":"Cross-Site Scripting","severity":"high","host":"example.com","matched-at":"http://example.com/","info":{"name":"Cross-Site Scripting","severity":"high"}}
{"template-id":"info-disclosure","name":"Info Disclosure","severity":"info","host":"example.com","matched-at":"http://example.com/info","info":{"name":"Info Disclosure","severity":"info"}}
invalid-json-here
{"template-id":"sqli","name":"SQL Injection","severity":"critical","host":"example.com","matched-at":"http://example.com/db","info":{"name":"SQL Injection","severity":"critical"}}`

	tests := []struct {
		name              string
		allowedSeverities []string
		verbose           bool
		expectedCount     int
		expectedTemplates []string
	}{
		{
			name:              "filter critical and high",
			allowedSeverities: []string{"critical", "high"},
			verbose:           false,
			expectedCount:     2,
			expectedTemplates: []string{"xss", "sqli"},
		},
		{
			name:              "filter high only",
			allowedSeverities: []string{"high"},
			verbose:           false,
			expectedCount:     1,
			expectedTemplates: []string{"xss"},
		},
		{
			name:              "filter info only",
			allowedSeverities: []string{"info"},
			verbose:           false,
			expectedCount:     1,
			expectedTemplates: []string{"info-disclosure"},
		},
		{
			name:              "filter none (empty allows defaults in caller, but here empty slice means no match)",
			allowedSeverities: []string{},
			verbose:           false,
			expectedCount:     0,
			expectedTemplates: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBufferString(inputJSONL)
			var logBuf bytes.Buffer
			opts := Options{
				Verbose:   tt.verbose,
				LogWriter: &logBuf,
			}
			findings, err := ParseAndFilterReader(buf, tt.allowedSeverities, opts)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(findings) != tt.expectedCount {
				t.Errorf("expected %d findings, got %d", tt.expectedCount, len(findings))
			}

			for i, expectedTpl := range tt.expectedTemplates {
				if i < len(findings) && findings[i].TemplateID != expectedTpl {
					t.Errorf("expected finding %d template to be %q, got %q", i, expectedTpl, findings[i].TemplateID)
				}
			}
		})
	}
}

func TestMalformedJSONLogging(t *testing.T) {
	inputJSONL := `invalid-json`
	var logBuf bytes.Buffer

	// Verbose false - should not print warning
	_, err := ParseAndFilterReader(bytes.NewBufferString(inputJSONL), []string{"high"}, Options{
		Verbose:   false,
		LogWriter: &logBuf,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logBuf.Len() > 0 {
		t.Errorf("expected no warning output, got: %s", logBuf.String())
	}

	// Verbose true - should print warning
	logBuf.Reset()
	_, err = ParseAndFilterReader(bytes.NewBufferString(inputJSONL), []string{"high"}, Options{
		Verbose:   true,
		LogWriter: &logBuf,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("[WARN] Skipping malformed Nuclei JSONL line")) {
		t.Errorf("expected warning output about malformed line, got: %s", logBuf.String())
	}
}

func TestParseAndFilterDetailed(t *testing.T) {
	inputJSONL := `{"template-id":"xss","name":"Cross-Site Scripting","severity":"high","host":"example.com","matched-at":"http://example.com/","info":{"name":"Cross-Site Scripting","severity":"high"}}
invalid-json-here`

	result, err := ParseAndFilterDetailed(bytes.NewBufferString(inputJSONL), []string{"high"}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalLines != 2 {
		t.Fatalf("expected TotalLines=2, got %d", result.TotalLines)
	}
	if result.MalformedLines != 1 {
		t.Fatalf("expected MalformedLines=1, got %d", result.MalformedLines)
	}
	if result.RawFindings != 1 {
		t.Fatalf("expected RawFindings=1, got %d", result.RawFindings)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestParseAndFilterDetailedCountsSeverityFilteredFindings(t *testing.T) {
	inputJSONL := `{"template-id":"info","name":"Info","severity":"info","info":{"name":"Info","severity":"info"}}
{"template-id":"high","name":"High","severity":"high","info":{"name":"High","severity":"high"}}`

	result, err := ParseAndFilterDetailed(bytes.NewBufferString(inputJSONL), []string{"high"}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RawFindings != 2 {
		t.Fatalf("expected RawFindings=2, got %d", result.RawFindings)
	}
	if result.FilteredBySeverity != 1 {
		t.Fatalf("expected FilteredBySeverity=1, got %d", result.FilteredBySeverity)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 retained finding, got %d", len(result.Findings))
	}
}

func TestParseAndFilterHelper(t *testing.T) {
	input := `{"template-id":"xss","name":"XSS","severity":"high","info":{"name":"XSS","severity":"high"}}`
	findings, err := ParseAndFilter(input, []string{"high"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].TemplateID != "xss" {
		t.Errorf("expected template-id 'xss', got %s", findings[0].TemplateID)
	}
}

func TestParserScannerLimit(t *testing.T) {
	// A line longer than standard token limit (e.g. 64KB) to verify buffer expansion
	largeLine := `{"template-id":"large","name":"Large","severity":"high","info":{"name":"Large","severity":"high"},"response":"` + strings.Repeat("A", 100*1024) + `"}`
	findings, err := ParseAndFilter(largeLine, []string{"high"})
	if err != nil {
		t.Fatalf("unexpected scanner error on large line: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestReaderErrorPropagation(t *testing.T) {
	errReader := &errorReader{}
	_, err := ParseAndFilterReader(errReader, []string{"high"}, Options{})
	if err == nil {
		t.Error("expected error from errReader, got nil")
	}
}

func TestWAFBlockedFindingDetection(t *testing.T) {
	inputJSONL := `{"template-id":"xss","name":"XSS Blocked","severity":"high","host":"example.com","matched-at":"http://example.com/","response":"Error 1015: You are being rate limited","info":{"name":"XSS Blocked","severity":"high"}}
{"template-id":"sqli","name":"SQL Injection","severity":"high","host":"example.com","matched-at":"http://example.com/db","response":"normal response body","info":{"name":"SQL Injection","severity":"high"}}
{"template-id":"lfi","name":"LFI Found","severity":"critical","host":"example.com","matched-at":"http://example.com/file","response":"Attention Required! | Cloudflare","info":{"name":"LFI Found","severity":"critical"}}`

	result, err := ParseAndFilterDetailed(bytes.NewBufferString(inputJSONL), []string{"high", "critical"}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.WAFBlocked != 2 {
		t.Fatalf("expected WAFBlocked=2, got %d", result.WAFBlocked)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 non-WAF-blocked finding, got %d", len(result.Findings))
	}
	if result.Findings[0].TemplateID != "sqli" {
		t.Errorf("expected remaining finding to be sqli, got %q", result.Findings[0].TemplateID)
	}
}

func TestWAFBlockedVerboseLogging(t *testing.T) {
	inputJSONL := `{"template-id":"xss","name":"XSS","severity":"high","response":"Access denied | freemodel.dev used Cloudflare to restrict access","info":{"name":"XSS","severity":"high"}}`
	var logBuf bytes.Buffer

	_, err := ParseAndFilterDetailed(bytes.NewBufferString(inputJSONL), []string{"high"}, Options{
		Verbose:   true,
		LogWriter: &logBuf,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(logBuf.Bytes(), []byte("[WARN] Skipping WAF-blocked finding")) {
		t.Errorf("expected WAF warning in verbose log, got: %s", logBuf.String())
	}
}

func TestNoFalseWAFPositives(t *testing.T) {
	inputJSONL := `{"template-id":"xss","name":"XSS","severity":"high","response":"HTTP/1.1 200 OK\r\n\r\nNormal page content","info":{"name":"XSS","severity":"high"}}`

	result, err := ParseAndFilterDetailed(bytes.NewBufferString(inputJSONL), []string{"high"}, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.WAFBlocked != 0 {
		t.Fatalf("expected WAFBlocked=0 for normal response, got %d", result.WAFBlocked)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrClosedPipe
}

func TestDeduplicateFindings(t *testing.T) {
	t.Run("same template-id merges into one", func(t *testing.T) {
		findings := []NucleiFinding{
			{TemplateID: "missing-header", Name: "Missing Header", Severity: "high", MatchedAt: "http://example.com/page1"},
			{TemplateID: "missing-header", Name: "Missing Header", Severity: "high", MatchedAt: "http://example.com/page2"},
			{TemplateID: "missing-header", Name: "Missing Header", Severity: "high", MatchedAt: "http://example.com/page3"},
		}

		result := DeduplicateFindings(findings)
		if len(result) != 1 {
			t.Fatalf("expected 1 deduplicated finding, got %d", len(result))
		}
		if result[0].Count != 3 {
			t.Fatalf("expected count=3, got %d", result[0].Count)
		}
		if len(result[0].AffectedURLs) != 3 {
			t.Fatalf("expected 3 affected URLs, got %d", len(result[0].AffectedURLs))
		}
	})

	t.Run("different template-ids remain separate", func(t *testing.T) {
		findings := []NucleiFinding{
			{TemplateID: "xss", Name: "XSS", Severity: "high", MatchedAt: "http://example.com/1"},
			{TemplateID: "sqli", Name: "SQLi", Severity: "critical", MatchedAt: "http://example.com/2"},
		}

		result := DeduplicateFindings(findings)
		if len(result) != 2 {
			t.Fatalf("expected 2 deduplicated findings, got %d", len(result))
		}
	})

	t.Run("preserves order of first occurrence", func(t *testing.T) {
		findings := []NucleiFinding{
			{TemplateID: "low-vuln", Name: "Low Vuln", Severity: "low", MatchedAt: "http://example.com/a"},
			{TemplateID: "high-vuln", Name: "High Vuln", Severity: "high", MatchedAt: "http://example.com/b"},
			{TemplateID: "low-vuln", Name: "Low Vuln", Severity: "low", MatchedAt: "http://example.com/c"},
		}

		result := DeduplicateFindings(findings)
		if len(result) != 2 {
			t.Fatalf("expected 2 deduplicated findings, got %d", len(result))
		}
		if result[0].Representative.TemplateID != "low-vuln" {
			t.Errorf("expected first to be low-vuln, got %q", result[0].Representative.TemplateID)
		}
		if result[1].Representative.TemplateID != "high-vuln" {
			t.Errorf("expected second to be high-vuln, got %q", result[1].Representative.TemplateID)
		}
	})

	t.Run("empty findings returns empty slice", func(t *testing.T) {
		result := DeduplicateFindings([]NucleiFinding{})
		if len(result) != 0 {
			t.Fatalf("expected 0 deduplicated findings, got %d", len(result))
		}
	})

	t.Run("keeps first finding as representative", func(t *testing.T) {
		findings := []NucleiFinding{
			{TemplateID: "xss", Name: "XSS", Severity: "high", MatchedAt: "http://a.com/1", Host: "a.com", CurlCommand: "curl http://a.com/1"},
			{TemplateID: "xss", Name: "XSS", Severity: "high", MatchedAt: "http://b.com/2", Host: "b.com", CurlCommand: "curl http://b.com/2"},
		}

		result := DeduplicateFindings(findings)
		if result[0].Representative.Host != "a.com" {
			t.Errorf("expected representative host to be a.com, got %q", result[0].Representative.Host)
		}
		if result[0].Representative.CurlCommand != "curl http://a.com/1" {
			t.Errorf("expected representative curl to be from first finding")
		}
	})

	t.Run("same name different template-ids are separate", func(t *testing.T) {
		findings := []NucleiFinding{
			{TemplateID: "tpl-a", Name: "Missing Header", Severity: "high", MatchedAt: "http://example.com/1"},
			{TemplateID: "tpl-b", Name: "Missing Header", Severity: "high", MatchedAt: "http://example.com/2"},
		}

		result := DeduplicateFindings(findings)
		if len(result) != 2 {
			t.Fatalf("expected 2 deduplicated findings (different template-ids), got %d", len(result))
		}
	})
}
