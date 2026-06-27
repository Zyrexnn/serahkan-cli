package runner

import (
	"runtime"
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
	path, err := resolveNucleiPath()
	if err != nil {
		t.Logf("resolveNucleiPath returned error (this is normal if nuclei is not installed and not in workspace during sandbox test run): %v", err)
	} else {
		t.Logf("resolveNucleiPath resolved path to: %s", path)
		if path == "" {
			t.Error("expected non-empty path when error is nil")
		}
	}
}
