package runner

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

func RunNuclei(ctx context.Context, target string) (string, error) {
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("nuclei is not installed or not available in PATH")
		}

		return "", fmt.Errorf("failed to locate nuclei: %w", err)
	}

	cmd := exec.CommandContext(ctx, nucleiPath, "-target", target, "-jsonl", "-silent")

	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("nuclei scan failed: %s", string(exitErr.Stderr))
		}

		return "", fmt.Errorf("failed to run nuclei: %w", err)
	}

	return string(output), nil
}
