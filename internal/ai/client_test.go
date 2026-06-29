package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cfgstore "github.com/Zyrexnn/serahkan-cli/internal/config"
)

func TestDefaultConfig(t *testing.T) {
	// Backup env vars
	origEndpoint := os.Getenv("SERAHKAN_AI_ENDPOINT")
	origModel := os.Getenv("SERAHKAN_AI_MODEL")
	origAPIKey := os.Getenv("SERAHKAN_AI_API_KEY")
	origConfig := os.Getenv("SERAHKAN_CONFIG")
	defer func() {
		os.Setenv("SERAHKAN_AI_ENDPOINT", origEndpoint)
		os.Setenv("SERAHKAN_AI_MODEL", origModel)
		os.Setenv("SERAHKAN_AI_API_KEY", origAPIKey)
		os.Setenv("SERAHKAN_CONFIG", origConfig)
	}()

	t.Run("default values when env is empty", func(t *testing.T) {
		os.Setenv("SERAHKAN_AI_ENDPOINT", "")
		os.Setenv("SERAHKAN_AI_MODEL", "")
		os.Setenv("SERAHKAN_AI_API_KEY", "")
		os.Setenv("SERAHKAN_CONFIG", filepath.Join(t.TempDir(), "config.json"))

		cfg := DefaultConfig()
		if cfg.Endpoint != defaultLocalAIEndpoint {
			t.Errorf("expected endpoint %q, got %q", defaultLocalAIEndpoint, cfg.Endpoint)
		}
		if cfg.Model != defaultLocalAIModel {
			t.Errorf("expected model %q, got %q", defaultLocalAIModel, cfg.Model)
		}
		if cfg.Timeout != defaultTimeout {
			t.Errorf("expected timeout %v, got %v", defaultTimeout, cfg.Timeout)
		}
	})

	t.Run("overridden values from env", func(t *testing.T) {
		customEndpoint := "http://custom-ai:8000/v1"
		customModel := "custom-deepseek-model"
		os.Setenv("SERAHKAN_AI_ENDPOINT", customEndpoint)
		os.Setenv("SERAHKAN_AI_MODEL", customModel)
		os.Setenv("SERAHKAN_AI_API_KEY", "")
		os.Setenv("SERAHKAN_CONFIG", filepath.Join(t.TempDir(), "config.json"))

		cfg := DefaultConfig()
		if cfg.Endpoint != customEndpoint {
			t.Errorf("expected endpoint %q, got %q", customEndpoint, cfg.Endpoint)
		}
		if cfg.Model != customModel {
			t.Errorf("expected model %q, got %q", customModel, cfg.Model)
		}
	})

	t.Run("uses config file when env is empty", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")
		os.Setenv("SERAHKAN_AI_ENDPOINT", "")
		os.Setenv("SERAHKAN_AI_MODEL", "")
		os.Setenv("SERAHKAN_AI_API_KEY", "")
		os.Setenv("SERAHKAN_CONFIG", configPath)

		err := cfgstore.SaveToPath(configPath, cfgstore.Config{
			AI: cfgstore.AIConfig{
				Endpoint:       "http://from-config:1234/v1/chat/completions",
				Model:          "from-config-model",
				APIKey:         "from-config-key",
				TimeoutSeconds: 90,
				RetryCount:     4,
			},
		})
		if err != nil {
			t.Fatalf("SaveToPath() error = %v", err)
		}

		cfg := DefaultConfig()
		if cfg.Endpoint != "http://from-config:1234/v1/chat/completions" {
			t.Fatalf("expected endpoint from config, got %q", cfg.Endpoint)
		}
		if cfg.Model != "from-config-model" {
			t.Fatalf("expected model from config, got %q", cfg.Model)
		}
		if cfg.ApiKey != "from-config-key" {
			t.Fatalf("expected api key from config, got %q", cfg.ApiKey)
		}
		if cfg.Timeout != 90*time.Second {
			t.Fatalf("expected timeout from config, got %v", cfg.Timeout)
		}
		if cfg.RetryCount != 4 {
			t.Fatalf("expected retry count from config, got %d", cfg.RetryCount)
		}
	})
}

func TestClassifyAIConnectionError(t *testing.T) {
	err := &url.Error{
		Op:  "Post",
		URL: "http://127.0.0.1:1234/v1/chat/completions",
		Err: &net.OpError{
			Err: errors.New("connect: connection refused"),
		},
	}

	classified := classifyAIConnectionError("http://127.0.0.1:1234/v1/chat/completions", err)
	if !strings.Contains(classified.Error(), "not accepting connections") {
		t.Fatalf("expected actionable connection-refused message, got %q", classified.Error())
	}
}

func TestSendToLocalAIValidation(t *testing.T) {
	cfg := Config{}

	_, err := SendToLocalAI(context.Background(), "hello", cfg)
	if err == nil || err.Error() != "AI endpoint cannot be empty" {
		t.Errorf("expected empty endpoint error, got: %v", err)
	}

	cfg.Endpoint = "http://localhost"
	_, err = SendToLocalAI(context.Background(), "hello", cfg)
	if err == nil || err.Error() != "AI model cannot be empty" {
		t.Errorf("expected empty model error, got: %v", err)
	}
}

func TestSendToLocalAIMockServer(t *testing.T) {
	expectedReply := "Mock AI Analysis Report"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request properties
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json header, got %s", r.Header.Get("Content-Type"))
		}

		var reqBody ChatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		if reqBody.Model != "test-model" {
			t.Errorf("expected model 'test-model', got %s", reqBody.Model)
		}
		if len(reqBody.Messages) != 2 {
			t.Errorf("expected 2 messages (system, user), got %d", len(reqBody.Messages))
		}

		// Send mock response
		resp := ChatCompletionResponse{
			Choices: []ChatCompletionChoice{
				{
					Message: ChatMessage{
						Role:    "assistant",
						Content: expectedReply,
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		Endpoint: server.URL,
		Model:    "test-model",
		Timeout:  5 * time.Second,
	}

	reply, err := SendToLocalAI(context.Background(), "some vulnerability input", cfg)
	if err != nil {
		t.Fatalf("unexpected error calling SendToLocalAI: %v", err)
	}

	if reply != expectedReply {
		t.Errorf("expected reply %q, got %q", expectedReply, reply)
	}
}

func TestSendToLocalAIErrorHandling(t *testing.T) {
	t.Run("server returns 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal server error message"))
		}))
		defer server.Close()

		cfg := Config{
			Endpoint: server.URL,
			Model:    "test-model",
		}

		_, err := SendToLocalAI(context.Background(), "vulnerability summary", cfg)
		if err == nil {
			t.Error("expected error from 500 response, got nil")
		}
	})

	t.Run("server returns empty choices", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := ChatCompletionResponse{
				Choices: []ChatCompletionChoice{},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := Config{
			Endpoint: server.URL,
			Model:    "test-model",
		}

		_, err := SendToLocalAI(context.Background(), "vulnerability summary", cfg)
		if err == nil || err.Error() != "local AI server returned no completion choices" {
			t.Errorf("expected no completion choices error, got: %v", err)
		}
	})

	t.Run("retries on transient server error", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("temporary failure"))
				return
			}

			resp := ChatCompletionResponse{
				Choices: []ChatCompletionChoice{
					{
						Message: ChatMessage{
							Role:    "assistant",
							Content: "Recovered response",
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		cfg := Config{
			Endpoint:   server.URL,
			Model:      "test-model",
			Timeout:    5 * time.Second,
			RetryCount: 1,
			RetryDelay: 10 * time.Millisecond,
		}

		reply, err := SendToLocalAI(context.Background(), "vulnerability summary", cfg)
		if err != nil {
			t.Fatalf("expected retry to recover, got error: %v", err)
		}
		if reply != "Recovered response" {
			t.Fatalf("expected recovered response, got %q", reply)
		}
		if attempts != 2 {
			t.Fatalf("expected 2 attempts, got %d", attempts)
		}
	})
}
