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
