package exporter

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestStripANSI(t *testing.T) {
	input := "\x1b[1;36mCyan Text\x1b[0m Normal"
	result := StripANSI(input)
	if result != "Cyan Text Normal" {
		t.Errorf("expected 'Cyan Text Normal', got %q", result)
	}

	clean := "No ANSI codes here"
	if StripANSI(clean) != clean {
		t.Error("expected clean text to remain unchanged")
	}
}

func TestSanitizeForHTML(t *testing.T) {
	input := `<script>alert("xss")</script>`
	result := SanitizeForHTML(input)
	if strings.Contains(result, "<script>") {
		t.Error("expected HTML tags to be escaped")
	}
	if !strings.Contains(result, "&lt;script&gt;") {
		t.Error("expected escaped HTML entities")
	}
}

func TestConvertANSIToHTML(t *testing.T) {
	input := "\x1b[1;36mCyan\x1b[0m Normal"
	result := ConvertANSIToHTML(input)
	if !strings.Contains(result, `<span class="ansi-cyan-bold">`) {
		t.Error("expected ANSI cyan class")
	}
	if !strings.Contains(result, "</span>") {
		t.Error("expected closing span tag")
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		target   string
		expected string
	}{
		{"http://example.com", "example_com"},
		{"https://sub.example.com/path", "sub_example_com"},
		{"http://192.168.1.1:8080", "192_168_1_1"},
		{"invalid", "unknown"},
	}

	for _, tt := range tests {
		result := ExtractHost(tt.target)
		if result != tt.expected {
			t.Errorf("ExtractHost(%q) = %q, want %q", tt.target, result, tt.expected)
		}
	}
}

func TestGenerateFilename(t *testing.T) {
	filename := GenerateFilename("http://example.com", "html")
	if !strings.HasPrefix(filename, "report_example_com_") {
		t.Errorf("expected filename to start with 'report_example_com_', got %q", filename)
	}
	if !strings.HasSuffix(filename, ".html") {
		t.Errorf("expected .html suffix, got %q", filename)
	}
}

func TestExportHTML(t *testing.T) {
	data := ReportData{
		Target:       "http://test.example.com",
		Findings:     "Test findings content",
		AISummary:    "AI analysis summary",
		ScanDuration: "30s",
		Timestamp:    time.Now(),
		FindingCount: 5,
		AIUsed:       true,
		AIStatus:     "ok",
	}

	savedPath, err := ExportHTML(data)
	if err != nil {
		t.Fatalf("ExportHTML error: %v", err)
	}
	defer os.Remove(savedPath)

	content, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read exported file: %v", err)
	}

	html := string(content)
	if !strings.Contains(html, "SERAHKAN") {
		t.Error("expected SERAHKAN in HTML output")
	}
	if !strings.Contains(html, "test.example.com") {
		t.Error("expected target host in HTML output")
	}
	if !strings.Contains(html, "meta-grid") {
		t.Error("expected meta-grid in HTML output")
	}
	if !strings.Contains(html, "footer") {
		t.Error("expected footer in HTML output")
	}
}

func TestExportMarkdown(t *testing.T) {
	data := ReportData{
		Target:       "http://test.example.com",
		Findings:     "Test findings content",
		AISummary:    "AI analysis summary",
		ScanDuration: "30s",
		Timestamp:    time.Now(),
		FindingCount: 5,
		AIUsed:       true,
		AIStatus:     "ok",
	}

	savedPath, err := ExportMarkdown(data)
	if err != nil {
		t.Fatalf("ExportMarkdown error: %v", err)
	}
	defer os.Remove(savedPath)

	content, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read exported file: %v", err)
	}

	md := string(content)
	if !strings.Contains(md, "# SERAHKAN Security Report") {
		t.Error("expected markdown header")
	}
	if !strings.Contains(md, "test.example.com") {
		t.Error("expected target in markdown output")
	}
	if strings.Contains(md, "\x1b") {
		t.Error("expected ANSI codes to be stripped from markdown")
	}
}

func TestExportFilenameTimestamp(t *testing.T) {
	before := time.Now().Format("20060102_150405")
	data := ReportData{
		Target:    "http://example.com",
		Timestamp: time.Now(),
	}

	savedPath, err := ExportHTML(data)
	if err != nil {
		t.Fatalf("ExportHTML error: %v", err)
	}
	defer os.Remove(savedPath)

	if !strings.Contains(savedPath, before[:8]) {
		t.Error("expected timestamp in filename")
	}
}

func TestSaveToFile(t *testing.T) {
	content := []byte("test content")
	savedPath, err := SaveToFile("test_output.txt", content)
	if err != nil {
		t.Fatalf("SaveToFile error: %v", err)
	}
	defer os.Remove(savedPath)

	readContent, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(readContent) != "test content" {
		t.Errorf("expected 'test content', got %q", string(readContent))
	}
}
