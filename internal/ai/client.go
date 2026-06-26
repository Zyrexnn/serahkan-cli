package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const localAIEndpoint = "http://127.0.0.1:1234/v1/chat/completions"

const localAIModel = "qwen2.5-coder-1.5b-instruct"

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
        $ [Real curl command, no hallucination]
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

func SendToLocalAI(prompt string) (string, error) {
	payload := ChatCompletionRequest{
		Model: localAIModel,
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

	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	req, err := http.NewRequest(http.MethodPost, localAIEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to reach local AI server at %s: %w", localAIEndpoint, err)
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
