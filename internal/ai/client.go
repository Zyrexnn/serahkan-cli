package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cfgstore "github.com/Zyrexnn/serahkan-cli/internal/config"
)

const defaultLocalAIEndpoint = "http://127.0.0.1:1234/v1/chat/completions"

const defaultLocalAIModel = "qwen2.5-coder-1.5b-instruct"

const defaultTimeout = 120 * time.Second

const defaultRetryCount = 2

const defaultRetryDelay = 2 * time.Second

const systemPrompt = `You are an elite automated DevSecOps AI agent and advanced source-code auditor built into the 'serahkan-cli' platform. Analyze raw vulnerability logs and output a highly technical, cyber-security-themed report.

STRICT OUTPUT RULE: Do not use markdown headers (#, ##). You MUST strictly replicate the ASCII format, dividers, and status brackets shown below:

+-------------------------------------------------------------------------+
|                      AI DEFENSIVE ANALYSIS REPORT                       |
+-------------------------------------------------------------------------+

[=] TARGET PROFILE
    - Target Host : [Extract Host]
    - Risk Status : [CLEAN / LOW RISK / HIGH ALERT]

[=] ROOT CAUSE ANALYSIS
    [Provide a 2-3 sentence technical overview here]

[=] ACTIVE VULNERABILITY AUDIT & MANUAL VALIDATION
===========================================================================
[!] FINDING X: [Name]
    - Risk Level  : [Severity]
    - Technical Overview: [Brief description]
    - Manual Proof-of-Concept Validation:
      * Execute Command:
        $ [Real curl command, NO HALLUCINATION. If a curl command was NOT provided in the input log, you MUST write "N/A". DO NOT construct or hallucinate a curl command.]
      * Expected Response Indicator: [What to check]
---------------------------------------------------------------------------

[=] REMEDIATION & HARDENING PLAYBOOK
===========================================================================
[*] ACTION X: [Title]
    - Targeted Component: [e.g., Nginx Config, Cloudflare]
    - Implementation Code:
      Input actual industry-standard configuration/code blocks here (e.g., real Nginx blocks or valid JS/PHP code). No hallucinated sed commands.
`

type ChatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatCompletionResponse struct {
	Choices []ChatCompletionChoice `json:"choices"`
}

type ChatCompletionChoice struct {
	Message ChatMessage `json:"message"`
}

type Config struct {
	Endpoint   string
	Model      string
	Timeout    time.Duration
	ApiKey     string
	RetryCount int
	RetryDelay time.Duration
}

func DefaultConfig() Config {
	fileConfig, _, err := cfgstore.Load()
	if err != nil {
		fileConfig = cfgstore.Config{}
	}

	endpoint := strings.TrimSpace(fileConfig.AI.Endpoint)
	model := strings.TrimSpace(fileConfig.AI.Model)
	apiKey := strings.TrimSpace(fileConfig.AI.APIKey)

	if envEndpoint := strings.TrimSpace(os.Getenv("SERAHKAN_AI_ENDPOINT")); envEndpoint != "" {
		endpoint = envEndpoint
	}
	if envModel := strings.TrimSpace(os.Getenv("SERAHKAN_AI_MODEL")); envModel != "" {
		model = envModel
	}
	if envAPIKey := strings.TrimSpace(os.Getenv("SERAHKAN_AI_API_KEY")); envAPIKey != "" {
		apiKey = envAPIKey
	}

	if endpoint == "" {
		endpoint = defaultLocalAIEndpoint
	}

	if model == "" {
		model = defaultLocalAIModel
	}

	timeout := defaultTimeout
	if fileConfig.AI.TimeoutSeconds > 0 {
		timeout = time.Duration(fileConfig.AI.TimeoutSeconds) * time.Second
	}

	retryCount := defaultRetryCount
	if fileConfig.AI.RetryCount > 0 {
		retryCount = fileConfig.AI.RetryCount
	}

	return Config{
		Endpoint:   endpoint,
		Model:      model,
		Timeout:    timeout,
		ApiKey:     apiKey,
		RetryCount: retryCount,
		RetryDelay: defaultRetryDelay,
	}
}

func SendToLocalAI(ctx context.Context, prompt string, config Config) (string, error) {
	if strings.TrimSpace(config.Endpoint) == "" {
		return "", fmt.Errorf("AI endpoint cannot be empty")
	}

	if strings.TrimSpace(config.Model) == "" {
		return "", fmt.Errorf("AI model cannot be empty")
	}

	if config.Timeout <= 0 {
		config.Timeout = defaultTimeout
	}
	if config.RetryCount < 0 {
		config.RetryCount = 0
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = defaultRetryDelay
	}

	payload := ChatCompletionRequest{
		Model: strings.TrimSpace(config.Model),
		Messages: []ChatMessage{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: strings.TrimSpace(prompt),
			},
		},
		Stream: false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode AI request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= config.RetryCount; attempt++ {
		content, err := sendSingleRequest(ctx, body, config)
		if err == nil {
			return content, nil
		}

		lastErr = err
		if !isRetryableAIError(err) || attempt == config.RetryCount {
			break
		}

		select {
		case <-ctx.Done():
			return "", fmt.Errorf("AI request canceled: %w", ctx.Err())
		case <-time.After(config.RetryDelay):
		}
	}

	return "", lastErr
}

func sendSingleRequest(ctx context.Context, body []byte, config Config) (string, error) {
	client := &http.Client{
		Timeout: config.Timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(config.Endpoint), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(config.ApiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(config.ApiKey))
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", classifyAIConnectionError(strings.TrimSpace(config.Endpoint), err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read AI response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("local AI server returned %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}

	var output ChatCompletionResponse
	if err := json.Unmarshal(responseBody, &output); err != nil {
		return "", fmt.Errorf("failed to decode AI response: %w", err)
	}

	if len(output.Choices) == 0 {
		return "", fmt.Errorf("local AI server returned no completion choices")
	}

	content := strings.TrimSpace(output.Choices[0].Message.Content)
	if content == "" {
		return "", fmt.Errorf("local AI server returned an empty completion")
	}

	return content, nil
}

func isRetryableAIError(err error) bool {
	if err == nil {
		return false
	}

	message := err.Error()
	if strings.Contains(message, "local AI server returned 5") {
		return true
	}
	if strings.Contains(message, "context deadline exceeded") {
		return true
	}
	if strings.Contains(message, "connection refused") {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}

func classifyAIConnectionError(endpoint string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		var opErr *net.OpError
		if errors.As(urlErr.Err, &opErr) {
			if strings.Contains(strings.ToLower(opErr.Err.Error()), "connection refused") {
				return fmt.Errorf("local AI server is not accepting connections at %s: %w. Ensure LM Studio or your OpenAI-compatible local server has started its HTTP server and is listening on that port", endpoint, err)
			}
		}
	}

	return fmt.Errorf("failed to reach local AI server at %s: %w", endpoint, err)
}
