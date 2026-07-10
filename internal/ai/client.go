package ai

import (
	"bufio"
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

const defaultTimeout = 25 * time.Second

const defaultRetryCount = 0

const defaultRetryDelay = 2 * time.Second

const systemPrompt = `You are an elite automated DevSecOps AI agent and advanced source-code auditor built into the 'serahkan-cli' platform. Analyze raw vulnerability logs and output a highly technical, cyber-security-themed report.

IMPORTANT: The input findings are deduplicated by vulnerability type. Each finding represents a unique vulnerability signature with multiple affected URLs listed. Analyze the root cause ONCE per vulnerability type and reference all affected URLs.

FALSE POSITIVE GUIDANCE:
- Do NOT flag DOM event listeners (addEventListener, removeEventListener) as vulnerabilities. These are standard JavaScript patterns used for normal UI interactivity, not security issues.
- The XSS-Protection header being deprecated does NOT mean the site is vulnerable to XSS. This is an informational finding. Report it as LOW RISK, not actionable.
- Distinguish between: (a) standard JS/CSS/HTML patterns detected by signature matching (low risk, informational only) vs (b) actual exploitable vulnerabilities with proof-of-concept (high risk).
- For informational findings without exploitable context, mark as 'NO ACTION REQUIRED' in the remediation section.

STRICT OUTPUT RULE:
- Do not use markdown headers (#, ##).
- Do not output decorative ASCII boxes, banner lines, or titles such as "AI DEFENSIVE ANALYSIS REPORT". The CLI renders those itself.
- Use ONLY the structured section markers below:

[=] TARGET PROFILE
    - Target Host : [Extract Host]
    - Risk Status : [CLEAN / LOW RISK / HIGH ALERT]

[=] ROOT CAUSE ANALYSIS
    [Provide a 2-3 sentence technical overview here]

[=] ACTIVE VULNERABILITY AUDIT & MANUAL VALIDATION
[!] FINDING X: [Name]
    - Risk Level  : [Severity]
    - Affected URLs:
      - [URL 1]
      - [URL 2]
    - Technical Overview: [Brief description. For informational findings, explicitly state "This is an informational finding with no exploitable vector."]
    - Manual Proof-of-Concept Validation:
      * Execute Command:
        $ [ACTUAL curl command from input. If a curl command was NOT provided in the input log, you MUST write "N/A". DO NOT construct or hallucinate a curl command under any circumstances.]
      * Expected Response Indicator: [Concrete indicator only, such as a specific header value, HTTP status, or response substring. If you cannot infer a reliable indicator from the finding, write "N/A".]

[=] REMEDIATION & HARDENING PLAYBOOK
[*] ACTION X: [Title]
    - Targeted Component: [e.g., Nginx Config, Cloudflare, Web Application]
    - Implementation Code:
      Input actual industry-standard configuration/code blocks here (e.g., real Nginx blocks with properly closed brackets, or valid JS/PHP code). All code blocks MUST be syntactically valid and complete. Do NOT use placeholder comments like "# Add your domain here" or "// Replace with your config". For informational findings with no remediation needed, write "NO ACTION REQUIRED - informational finding only".

SPECIAL HANDLING FOR INFORMATIONAL FINDINGS:
- For DOM event listener detections, clearly state this is normal JavaScript behavior and not an exploitable issue.
- For deprecated X-XSS-Protection headers, classify as informational only unless the input provides evidence of exploitability.
- Informational findings must keep their original low/info severity and must not be escalated to HIGH ALERT without concrete evidence.
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

type ChatCompletionStreamResponse struct {
	Choices []ChatCompletionStreamChoice `json:"choices"`
}

type ChatCompletionStreamChoice struct {
	Delta        ChatCompletionStreamDelta `json:"delta"`
	FinishReason *string                   `json:"finish_reason"`
}

type ChatCompletionStreamDelta struct {
	Role    string `json:"role"`
	Content string `json:"content"`
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

func StreamToLocalAI(ctx context.Context, prompt string, config Config, onToken func(string)) (string, error) {
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
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: strings.TrimSpace(prompt)},
		},
		Stream: true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode AI request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= config.RetryCount; attempt++ {
		content, err := sendStreamingRequest(ctx, body, config, onToken)
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

func sendStreamingRequest(ctx context.Context, body []byte, config Config, onToken func(string)) (string, error) {
	transport := &http.Transport{
		ResponseHeaderTimeout: config.Timeout,
	}
	client := &http.Client{
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(config.Endpoint), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if strings.TrimSpace(config.ApiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(config.ApiKey))
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", classifyAIConnectionError(strings.TrimSpace(config.Endpoint), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("local AI server returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	var accumulated strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}
		if line == "data: [DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		var chunk ChatCompletionStreamResponse
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}

		if len(chunk.Choices) == 0 {
			continue
		}

		delta := chunk.Choices[0].Delta
		if delta.Content == "" {
			continue
		}

		accumulated.WriteString(delta.Content)
		if onToken != nil {
			onToken(delta.Content)
		}
	}

	if err := scanner.Err(); err != nil {
		return accumulated.String(), fmt.Errorf("failed to read AI stream: %w", err)
	}

	return accumulated.String(), nil
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
