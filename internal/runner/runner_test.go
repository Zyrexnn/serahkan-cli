package runner

import (
	"runtime"
	"strings"
	"testing"
)

func TestLocalNucleiCandidates(t *testing.T) {
	candidates := localNucleiCandidates()
	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(candidates))
	}

	if runtime.GOOS == "windows" {
		if candidates[0] != "nuclei.exe" {
			t.Errorf("expected first candidate on Windows to be nuclei.exe, got %s", candidates[0])
		}
	} else {
		if candidates[0] != "nuclei" {
			t.Errorf("expected first candidate on non-Windows to be nuclei, got %s", candidates[0])
		}
	}
}

func TestResolveNucleiPath(t *testing.T) {
	path, err := ResolveNucleiPath()
	if err != nil {
		t.Logf("ResolveNucleiPath returned error (this is normal if nuclei is not installed and not in workspace during sandbox test run): %v", err)
	} else {
		t.Logf("ResolveNucleiPath resolved path to: %s", path)
		if path == "" {
			t.Error("expected non-empty path when error is nil")
		}
	}
}

func TestBuildNucleiArgs(t *testing.T) {
	nucleiFlagSupportMu.Lock()
	nucleiFlagSupport = map[string]map[string]bool{
		"/tmp/nuclei": {
			"-no-banner": true,
		},
		"/tmp/nuclei-no-bannerless": {
			"-no-banner": false,
		},
	}
	nucleiFlagSupportMu.Unlock()

	withBannerFlag := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 30,
		Retries:        2,
		NoInteractsh:   true,
		IncludeHTTP:    true,
	})
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-no-banner") {
		t.Fatalf("expected -no-banner to be included when supported")
	}
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-ni") {
		t.Fatalf("expected -ni to be included when NoInteractsh is true")
	}
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-irr") {
		t.Fatalf("expected -irr to be included when IncludeHTTP is true")
	}

	withoutBannerFlag := buildNucleiArgs("/tmp/nuclei-no-bannerless", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 30,
		Retries:        2,
	})
	if strings.Contains(strings.Join(withoutBannerFlag, " "), "-no-banner") {
		t.Fatalf("expected -no-banner to be omitted when unsupported")
	}
	if strings.Contains(strings.Join(withoutBannerFlag, " "), "-irr") {
		t.Fatalf("expected -irr to be omitted by default")
	}
	if !strings.Contains(strings.Join(withoutBannerFlag, " "), "-omit-raw") {
		t.Fatalf("expected -omit-raw to be included by default")
	}

	webArgs := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"info", "low", "medium", "high", "critical"}, Options{
		TimeoutSeconds:            30,
		Retries:                   1,
		Concurrency:               300,
		RateLimit:                 800,
		EnableHeadless:            true,
		EnableDAST:                true,
		AutomaticScan:             true,
		IncludeDefaultIgnoredTags: []string{"fuzz"},
		Headers:                   []string{"Authorization: Bearer token"},
		Cookie:                    "sid=abc",
		Tags:                      []string{"xss,sqli"},
		ExcludeTags:               []string{"dos"},
		Templates:                 []string{"http/exposures"},
		Workflows:                 []string{"workflows/test.yaml"},
		Types:                     []string{"http,headless"},
	})
	webJoined := strings.Join(webArgs, " ")
	expectedParts := []string{
		"-headless",
		"-dast",
		"-as",
		"-c 300",
		"-rl 800",
		"-itags fuzz",
		"-H Authorization: Bearer token",
		"-H Cookie: sid=abc",
		"-tags xss,sqli",
		"-etags dos",
		"-t http/exposures",
		"-w workflows/test.yaml",
		"-type http,headless",
	}
	for _, expected := range expectedParts {
		if !strings.Contains(webJoined, expected) {
			t.Fatalf("expected args to contain %q, got %q", expected, webJoined)
		}
	}

	parityArgs := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 30,
		Retries:        1,
		NoInteractsh:   true,
		ParityMode:     true,
	})
	parityJoined := strings.Join(parityArgs, " ")
	unexpectedParityParts := []string{"-c ", "-rl ", "-omit-raw", "-no-banner"}
	for _, unexpected := range unexpectedParityParts {
		if strings.Contains(parityJoined, unexpected) {
			t.Fatalf("expected parity args to omit %q, got %q", unexpected, parityJoined)
		}
	}
	if !strings.Contains(parityJoined, "-ni") {
		t.Fatalf("expected parity args to preserve requested -ni, got %q", parityJoined)
	}

	showCmdArgs := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
		ShowCommand:    true,
	})
	showCmdJoined := strings.Join(showCmdArgs, " ")
	if strings.Contains(showCmdJoined, "-silent") {
		t.Fatalf("expected -silent to be omitted when ShowCommand is true, got %q", showCmdJoined)
	}

	normalArgs := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
		ShowCommand:    false,
	})
	normalJoined := strings.Join(normalArgs, " ")
	if !strings.Contains(normalJoined, "-silent") {
		t.Fatalf("expected -silent to be included when ShowCommand is false, got %q", normalJoined)
	}
}

func TestIsAutomaticScanNoTemplateError(t *testing.T) {
	stderr := "[FTL] Could not run nuclei: could not create automatic scan service: could not find any templates with tech tag"
	if !isAutomaticScanNoTemplateError(stderr) {
		t.Fatalf("expected automatic scan no-template error to be detected")
	}

	if isAutomaticScanNoTemplateError("[FTL] unrelated nuclei failure") {
		t.Fatalf("expected unrelated error to be ignored")
	}
}
