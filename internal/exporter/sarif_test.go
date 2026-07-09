package exporter

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
)

func TestExportSarifCreatesFile(t *testing.T) {
	findings := []parser.NucleiFinding{
		{
			TemplateID:  "xss-detection",
			Name:        "Cross-Site Scripting",
			Severity:    "high",
			MatchedAt:   "https://example.com/search?q=test",
			Host:        "example.com",
			CurlCommand: "curl -X GET 'https://example.com/search?q=<script>'",
			Info: parser.NucleiInfo{
				Name:        "Cross-Site Scripting",
				Severity:    "high",
				Description: "Reflected XSS vulnerability in search parameter",
			},
		},
		{
			TemplateID: "xss-detection",
			Name:       "Cross-Site Scripting",
			Severity:   "high",
			MatchedAt:  "https://example.com/contact?name=test",
			Host:       "example.com",
			Info: parser.NucleiInfo{
				Name:        "Cross-Site Scripting",
				Severity:    "high",
				Description: "Reflected XSS vulnerability in contact name parameter",
			},
		},
		{
			TemplateID: "info-disclosure",
			Name:       "Information Disclosure",
			Severity:   "medium",
			MatchedAt:  "https://example.com/.env",
			Host:       "example.com",
			Info: parser.NucleiInfo{
				Name:        "Information Disclosure",
				Severity:    "medium",
				Description: "Environment file exposed",
			},
		},
	}

	savedPath, err := ExportSarif(findings, "https://example.com", "dev")
	if err != nil {
		t.Fatalf("ExportSarif error: %v", err)
	}
	defer os.Remove(savedPath)

	content, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read SARIF output: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(content, &result); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	if result["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", result["version"])
	}

	runs, ok := result["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("expected at least one run in SARIF output")
	}

	run := runs[0].(map[string]interface{})
	rules, _ := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})["rules"].([]interface{})
	if len(rules) != 2 {
		t.Errorf("expected 2 unique rules (xss-detection, info-disclosure), got %d", len(rules))
	}

	res, _ := run["results"].([]interface{})
	if len(res) != 3 {
		t.Errorf("expected 3 results, got %d", len(res))
	}

	for _, r := range res {
		resMap := r.(map[string]interface{})
		level, _ := resMap["level"].(string)
		if level != "error" && level != "warning" {
			t.Errorf("expected level 'error' or 'warning', got %q", level)
		}
	}
}

func TestExportSarifEmptyFindings(t *testing.T) {
	savedPath, err := ExportSarif([]parser.NucleiFinding{}, "https://example.com", "dev")
	if err != nil {
		t.Fatalf("ExportSarif with empty findings error: %v", err)
	}
	defer os.Remove(savedPath)

	content, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read SARIF output: %v", err)
	}

	if !strings.Contains(string(content), `"results": []`) {
		t.Error("expected empty results array in SARIF output")
	}
}

func TestSeverityToSarifLevel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "error"},
		{"low", "warning"},
		{"info", "note"},
		{"unknown", "note"},
	}
	for _, tt := range tests {
		got := severityToSarifLevel(tt.severity)
		if got != tt.expected {
			t.Errorf("severityToSarifLevel(%q) = %q, want %q", tt.severity, got, tt.expected)
		}
	}
}
