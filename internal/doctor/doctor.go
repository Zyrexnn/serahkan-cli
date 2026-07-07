package doctor

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/ai"
	"github.com/Zyrexnn/serahkan-cli/internal/runner"
)

type CheckResult struct {
	Name       string
	Status     string
	Details    string
	Latency    time.Duration
	DebugLines []string
}

func CheckNuclei() CheckResult {
	path, err := runner.ResolveNucleiPath()
	if err != nil {
		return CheckResult{
			Name:    "nuclei",
			Status:  "FAIL",
			Details: err.Error(),
		}
	}

	return CheckResult{
		Name:    "nuclei",
		Status:  "OK",
		Details: fmt.Sprintf("found at %s", path),
	}
}

func CheckAI(ctx context.Context, config ai.Config) CheckResult {
	endpoint := strings.TrimSpace(config.Endpoint)
	if endpoint == "" {
		return CheckResult{
			Name:    "ai",
			Status:  "FAIL",
			Details: "AI endpoint cannot be empty",
		}
	}

	if strings.TrimSpace(config.Model) == "" {
		return CheckResult{
			Name:    "ai",
			Status:  "FAIL",
			Details: "AI model cannot be empty",
		}
	}

	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return CheckResult{
			Name:    "ai",
			Status:  "FAIL",
			Details: fmt.Sprintf("invalid AI endpoint: %v", err),
		}
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return CheckResult{
			Name:    "ai",
			Status:  "FAIL",
			Details: fmt.Sprintf("unsupported AI endpoint scheme %q", parsedURL.Scheme),
		}
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	probeConfig := config
	probeConfig.Timeout = timeout

	startedAt := time.Now()
	_, err = ai.SendToLocalAI(reqCtx, "health check", probeConfig)
	latency := time.Since(startedAt)

	result := CheckResult{
		Name:    "ai",
		Latency: latency,
		DebugLines: []string{
			fmt.Sprintf("endpoint=%s", endpoint),
			fmt.Sprintf("model=%s", config.Model),
			fmt.Sprintf("timeout=%s", timeout.Round(time.Second)),
			fmt.Sprintf("retry_count=%d", config.RetryCount),
			fmt.Sprintf("chat_latency=%s", latency.Round(time.Millisecond)),
		},
	}

	if err != nil {
		result.Status = "FAIL"
		result.Details = fmt.Sprintf("AI server probe failed for %s with model %s: %v", endpoint, config.Model, err)
		return result
	}

	result.Status = "OK"
	result.Details = fmt.Sprintf("chat completion succeeded at %s with model %s", endpoint, config.Model)
	return result
}
