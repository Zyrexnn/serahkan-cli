package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
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

type ScanConfig struct {
	RateLimit     int    `yaml:"rate-limit"`
	Concurrency   int    `yaml:"concurrency"`
	AIEndpoint    string `yaml:"ai-endpoint"`
	AIModel       string `yaml:"ai-model"`
	TimeoutSeconds int   `yaml:"timeout_seconds"`
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

func LoadScanConfig() ScanConfig {
	return loadScanConfigWithDirs(func() (string, error) { return os.Getwd() }, func() (string, error) { return os.UserHomeDir() })
}

func loadScanConfigWithDirs(wdFn func() (string, error), homeFn func() (string, error)) ScanConfig {
	var cfg ScanConfig

	if path, err := findConfigYAMLWithDirs(wdFn, homeFn); err == nil && path != "" {
		data, readErr := os.ReadFile(path)
		if readErr == nil {
			_ = yaml.Unmarshal(data, &cfg)
			if cfg.AIEndpoint == "" && cfg.AIModel == "" {
				var fallback struct {
					AI struct {
						Endpoint      string `yaml:"endpoint"`
						Model         string `yaml:"model"`
						TimeoutSeconds int   `yaml:"timeout_seconds"`
					} `yaml:"ai"`
				}
				if err := yaml.Unmarshal(data, &fallback); err == nil {
					if fallback.AI.Endpoint != "" {
						cfg.AIEndpoint = fallback.AI.Endpoint
					}
					if fallback.AI.Model != "" {
						cfg.AIModel = fallback.AI.Model
					}
					if cfg.TimeoutSeconds == 0 && fallback.AI.TimeoutSeconds > 0 {
						cfg.TimeoutSeconds = fallback.AI.TimeoutSeconds
					}
				}
			}
		}
	}

	return cfg
}

func findConfigYAML() (string, error) {
	return findConfigYAMLWithDirs(func() (string, error) { return os.Getwd() }, func() (string, error) { return os.UserHomeDir() })
}

func findConfigYAMLWithDirs(wdFn func() (string, error), homeFn func() (string, error)) (string, error) {
	if wd, err := wdFn(); err == nil {
		local := filepath.Join(wd, "config.yaml")
		if _, err := os.Stat(local); err == nil {
			return local, nil
		}
	}

	if home, err := homeFn(); err == nil {
		homePath := filepath.Join(home, "config.yaml")
		if _, err := os.Stat(homePath); err == nil {
			return homePath, nil
		}
	}

	return "", fmt.Errorf("no config.yaml found")
}

func ConfigYAMLPath() (string, error) {
	if wd, err := os.Getwd(); err == nil {
		local := filepath.Join(wd, "config.yaml")
		if _, err := os.Stat(local); err == nil {
			return local, nil
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		homePath := filepath.Join(home, "config.yaml")
		if _, err := os.Stat(homePath); err == nil {
			return homePath, nil
		}
	}

	return "", fmt.Errorf("cannot determine config.yaml path")
}

func SaveScanConfig(cfg ScanConfig) (string, error) {
	path, err := ConfigYAMLPath()
	if err != nil {
		return "", err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to encode scan config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	return path, nil
}
