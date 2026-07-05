package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingConfigReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")

	cfg, err := LoadFromPath(path)
	if err != nil {
		t.Fatalf("expected nil error for missing config, got %v", err)
	}

	if cfg.AI.Endpoint != "" || cfg.AI.Model != "" || cfg.AI.APIKey != "" {
		t.Fatalf("expected zero-value config, got %+v", cfg)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	input := Config{
		AI: AIConfig{
			Endpoint:       "http://127.0.0.1:1234/v1/chat/completions",
			Model:          "qwen-test",
			APIKey:         "secret",
			TimeoutSeconds: 180,
			RetryCount:     3,
		},
	}

	if err := SaveToPath(path, input); err != nil {
		t.Fatalf("SaveToPath() error = %v", err)
	}

	output, err := LoadFromPath(path)
	if err != nil {
		t.Fatalf("LoadFromPath() error = %v", err)
	}

	if output != input {
		t.Fatalf("round-trip mismatch: got %+v want %+v", output, input)
	}
}

func TestPathUsesOverride(t *testing.T) {
	orig := os.Getenv(envConfigPath)
	t.Cleanup(func() {
		_ = os.Setenv(envConfigPath, orig)
	})

	override := filepath.Join(t.TempDir(), "serahkan.json")
	if err := os.Setenv(envConfigPath, override); err != nil {
		t.Fatalf("Setenv() error = %v", err)
	}

	path, err := Path()
	if err != nil {
		t.Fatalf("Path() error = %v", err)
	}

	if path != override {
		t.Fatalf("Path() = %q, want %q", path, override)
	}
}

func TestLoadScanConfigReturnsZeroWhenNoFile(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := filepath.Join(t.TempDir(), "fakehome")

	wdFn := func() (string, error) { return tmpDir, nil }
	homeFn := func() (string, error) { return homeDir, nil }

	cfg := loadScanConfigWithDirs(wdFn, homeFn)
	if cfg.RateLimit != 0 || cfg.Concurrency != 0 {
		t.Fatalf("expected zero-value scan config, got %+v", cfg)
	}
}

func TestLoadScanConfigFromProjectRoot(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := filepath.Join(t.TempDir(), "fakehome")

	wdFn := func() (string, error) { return tmpDir, nil }
	homeFn := func() (string, error) { return homeDir, nil }

	yamlContent := "rate-limit: 800\nconcurrency: 300\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("failed to write config.yaml: %v", err)
	}

	cfg := loadScanConfigWithDirs(wdFn, homeFn)
	if cfg.RateLimit != 800 {
		t.Fatalf("expected rate-limit=800, got %d", cfg.RateLimit)
	}
	if cfg.Concurrency != 300 {
		t.Fatalf("expected concurrency=300, got %d", cfg.Concurrency)
	}
}

func TestLoadScanConfigFromHomeDir(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := t.TempDir()

	wdFn := func() (string, error) { return tmpDir, nil }
	homeFn := func() (string, error) { return homeDir, nil }

	yamlContent := "rate-limit: 400\nconcurrency: 150\n"
	if err := os.WriteFile(filepath.Join(homeDir, "config.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("failed to write config.yaml: %v", err)
	}

	cfg := loadScanConfigWithDirs(wdFn, homeFn)
	if cfg.RateLimit != 400 {
		t.Fatalf("expected rate-limit=400, got %d", cfg.RateLimit)
	}
	if cfg.Concurrency != 150 {
		t.Fatalf("expected concurrency=150, got %d", cfg.Concurrency)
	}
}

func TestProjectRootOverridesHomeDir(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := t.TempDir()

	wdFn := func() (string, error) { return tmpDir, nil }
	homeFn := func() (string, error) { return homeDir, nil }

	homeYAML := "rate-limit: 400\nconcurrency: 150\n"
	if err := os.WriteFile(filepath.Join(homeDir, "config.yaml"), []byte(homeYAML), 0o644); err != nil {
		t.Fatalf("failed to write home config.yaml: %v", err)
	}

	localYAML := "rate-limit: 900\nconcurrency: 500\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(localYAML), 0o644); err != nil {
		t.Fatalf("failed to write local config.yaml: %v", err)
	}

	cfg := loadScanConfigWithDirs(wdFn, homeFn)
	if cfg.RateLimit != 900 {
		t.Fatalf("expected project root rate-limit=900, got %d", cfg.RateLimit)
	}
	if cfg.Concurrency != 500 {
		t.Fatalf("expected project root concurrency=500, got %d", cfg.Concurrency)
	}
}

func TestFindConfigYAMLProjectRootPriority(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := t.TempDir()

	wdFn := func() (string, error) { return tmpDir, nil }
	homeFn := func() (string, error) { return homeDir, nil }

	localYAML := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(localYAML, []byte("rate-limit: 100\n"), 0o644); err != nil {
		t.Fatalf("failed to write config.yaml: %v", err)
	}

	path, err := findConfigYAMLWithDirs(wdFn, homeFn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != localYAML {
		t.Fatalf("expected project root path %q, got %q", localYAML, path)
	}
}
