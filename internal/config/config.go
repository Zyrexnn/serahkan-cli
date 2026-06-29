package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const envConfigPath = "SERAHKAN_CONFIG"

type Config struct {
	AI AIConfig `json:"ai"`
}

type AIConfig struct {
	Endpoint       string `json:"endpoint"`
	Model          string `json:"model"`
	APIKey         string `json:"api_key"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	RetryCount     int    `json:"retry_count"`
}

func Load() (Config, string, error) {
	path, err := Path()
	if err != nil {
		return Config{}, "", err
	}

	cfg, err := LoadFromPath(path)
	return cfg, path, err
}

func LoadFromPath(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, fmt.Errorf("config path cannot be empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

func Save(cfg Config) (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}

	return path, SaveToPath(path, cfg)
}

func SaveToPath(path string, cfg Config) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("config path cannot be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func Path() (string, error) {
	if override := strings.TrimSpace(os.Getenv(envConfigPath)); override != "" {
		return override, nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve user config dir: %w", err)
	}

	return filepath.Join(dir, "serahkan", "config.json"), nil
}
