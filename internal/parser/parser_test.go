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
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
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

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrClosedPipe
}
