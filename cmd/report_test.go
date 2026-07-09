package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func executeReport(t *testing.T, args ...string) error {
	t.Helper()
	reportOpts = reportOptions{}
	rootCmd.SetArgs(args)
	out := new(bytes.Buffer)
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	return rootCmd.Execute()
}

func makeTempJSON(t *testing.T, report scanJSONReport) string {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write error: %v", err)
	}
	return path
}

func TestReportCommandBasic(t *testing.T) {
	report := scanJSONReport{
		Target:             "https://example.com",
		Severities:         []string{"medium", "high", "critical"},
		FindingCount:       2,
		RawFindings:        10,
		Profile:            "balanced",
		AuthMode:           "none",
		AIUsed:             true,
		AIStatus:           "ok",
		AIAnalysis:         "[=] TARGET PROFILE\n    - Risk Status : CLEAN\n",
		DurationSeconds:    30,
		GeneratedAtUnixUTC: 1700000000,
	}

	inputFile := makeTempJSON(t, report)
	outputFile := filepath.Join(filepath.Dir(inputFile), "output.html")

	err := executeReport(t, "report", "--input", inputFile, "--format", "html", "--output", outputFile)
	if err != nil {
		t.Fatalf("report command failed: %v", err)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("expected output file %s to exist", outputFile)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	html := string(content)
	if !strings.Contains(html, "SERAHKAN") {
		t.Error("expected SERAHKAN in HTML output")
	}
	if !strings.Contains(html, "example.com") {
		t.Error("expected target in HTML output")
	}
}

func TestReportCommandMarkdown(t *testing.T) {
	report := scanJSONReport{
		Target:             "https://test.example.com",
		Severities:         []string{"high", "critical"},
		FindingCount:       1,
		Profile:            "fast",
		AuthMode:           "none",
		AIStatus:           "not_used",
		DurationSeconds:    10,
		GeneratedAtUnixUTC: 1700000000,
	}

	inputFile := makeTempJSON(t, report)
	outputFile := filepath.Join(filepath.Dir(inputFile), "output.md")

	err := executeReport(t, "report", "--input", inputFile, "--format", "markdown", "--output", outputFile)
	if err != nil {
		t.Fatalf("report command (markdown) failed: %v", err)
	}

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Fatalf("expected output file %s to exist", outputFile)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	md := string(content)
	if !strings.Contains(md, "SERAHKAN Security Report") {
		t.Error("expected markdown header")
	}
	if !strings.Contains(md, "test.example.com") {
		t.Error("expected target in markdown output")
	}
}

func TestReportCommandInvalidInput(t *testing.T) {
	err := executeReport(t, "report", "--input", "nonexistent.json")
	if err == nil {
		t.Fatal("expected error for nonexistent input file")
	}
}

func TestReportCommandInvalidFormat(t *testing.T) {
	report := scanJSONReport{Target: "https://example.com"}
	inputFile := makeTempJSON(t, report)

	err := executeReport(t, "report", "--input", inputFile, "--format", "pdf")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestReportCommandEmptyFindings(t *testing.T) {
	report := scanJSONReport{
		Target:             "https://example.com",
		FindingCount:       0,
		Profile:            "fast",
		AIStatus:           "not_used",
		SkippedReasons:     []string{"No targets matched"},
		DurationSeconds:    5,
		GeneratedAtUnixUTC: 1700000000,
	}

	inputFile := makeTempJSON(t, report)
	err := executeReport(t, "report", "--input", inputFile)
	if err != nil {
		t.Fatalf("report with empty findings should succeed: %v", err)
	}
}
