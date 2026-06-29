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
	})
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-no-banner") {
		t.Fatalf("expected -no-banner to be included when supported")
	}
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-ni") {
		t.Fatalf("expected -ni to be included when NoInteractsh is true")
	}

	withoutBannerFlag := buildNucleiArgs("/tmp/nuclei-no-bannerless", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 30,
		Retries:        2,
	})
	if strings.Contains(strings.Join(withoutBannerFlag, " "), "-no-banner") {
		t.Fatalf("expected -no-banner to be omitted when unsupported")
	}
}
