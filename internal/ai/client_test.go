package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	// Backup env vars
	origEndpoint := os.Getenv("SERAHKAN_AI_ENDPOINT")
	origModel := os.Getenv("SERAHKAN_AI_MODEL")
	defer func() {
		os.Setenv("SERAHKAN_AI_ENDPOINT", origEndpoint)
		os.Setenv("SERAHKAN_AI_MODEL", origModel)
	}()

	t.Run("default values when env is empty", func(t *testing.T) {
		os.Setenv("SERAHKAN_AI_ENDPOINT", "")
		os.Setenv("SERAHKAN_AI_MODEL", "")

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

		cfg := DefaultConfig()
		if cfg.Endpoint != customEndpoint {
			t.Errorf("expected endpoint %q, got %q", customEndpoint, cfg.Endpoint)
		}
		if cfg.Model != customModel {
			t.Errorf("expected model %q, got %q", customModel, cfg.Model)
		}
	})
}

func TestSendToLocalAIValidation(t *testing.T) {
	cfg := Config{}

	_, err := SendToLocalAI("hello", cfg)
	if err == nil || err.Error() != "AI endpoint cannot be empty" {
		t.Errorf("expected empty endpoint error, got: %v", err)
	}

	cfg.Endpoint = "http://localhost"
	_, err = SendToLocalAI("hello", cfg)
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

	reply, err := SendToLocalAI("some vulnerability input", cfg)
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

		_, err := SendToLocalAI("vulnerability summary", cfg)
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

		_, err := SendToLocalAI("vulnerability summary", cfg)
		if err == nil || err.Error() != "local AI server returned no completion choices" {
			t.Errorf("expected no completion choices error, got: %v", err)
		}
	})
}
