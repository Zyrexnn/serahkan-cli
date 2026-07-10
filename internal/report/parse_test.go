package report

import (
	"strings"
	"testing"
)

func TestParseSkipsDecorativeAIHeader(t *testing.T) {
	raw := "+-------------------------------------------------------------------------+\n" +
		"|                      AI DEFENSIVE ANALYSIS REPORT                       |\n" +
		"+-------------------------------------------------------------------------+\n\n" +
		"[=] TARGET PROFILE\n" +
		"    - Target Host : example.com\n\n" +
		"[!] FINDING 1: Sample\n" +
		"    - Risk Level  : info\n" +
		"    - Affected URLs:\n" +
		"      - https://example.com\n" +
		"    - Manual Proof-of-Concept Validation:\n" +
		"      * Execute Command:\n" +
		"        $ N/A\n\n" +
		"[=] REMEDIATION & HARDENING PLAYBOOK\n" +
		"===========================================================================\n" +
		"[*] ACTION 1: NO ACTION REQUIRED\n" +
		"    - Targeted Component: Web Application\n" +
		"    - Implementation Code:\n" +
		"      ```\n" +
		"      N/A\n" +
		"      ```\n"

	sections := Parse(raw)
	if len(sections) != 4 {
		t.Fatalf("expected 4 sections, got %d", len(sections))
	}
	if sections[0].Title != "TARGET PROFILE" {
		t.Fatalf("expected first section TARGET PROFILE, got %q", sections[0].Title)
	}
	if strings.Contains(sections[0].Content, "AI DEFENSIVE ANALYSIS REPORT") {
		t.Fatal("expected decorative AI header to be removed")
	}
}

func TestParseCapturesCodeBlocks(t *testing.T) {
	raw := "[=] REMEDIATION & HARDENING PLAYBOOK\n" +
		"[*] ACTION 1: Sample\n" +
		"    - Implementation Code:\n" +
		"      ```\n" +
		"      add_header 'X-XSS-Protection' '0';\n" +
		"      ```\n"

	sections := Parse(raw)
	if len(sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(sections))
	}
	foundCode := false
	for _, item := range sections[1].Items {
		if item.IsCode {
			foundCode = true
			if !strings.Contains(item.Value, "add_header") {
				t.Fatalf("expected code block content, got %q", item.Value)
			}
		}
	}
	if !foundCode {
		t.Fatal("expected code block item")
	}
}
