package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
)

func RunNuclei(ctx context.Context, target string, allowedSeverities []string) ([]parser.NucleiFinding, error) {
	nucleiPath, err := resolveNucleiPath()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, nucleiPath, "-target", target, "-jsonl", "-severity", strings.Join(allowedSeverities, ","), "-timeout", "10", "-retries", "2", "-ni", "-leave-default-ports")
	cmd.Stderr = os.Stderr

	fmt.Println("[DEBUG] Nuclei executable:", nucleiPath)
	fmt.Println("[DEBUG] Nuclei args:", cmd.Args[1:])
	fmt.Println("[DEBUG] Full command:", strings.Join(cmd.Args, " "))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open nuclei stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("[ERROR] Failed to start nuclei:", err)
		return nil, fmt.Errorf("failed to start nuclei: %w", err)
	}

	findings, parseErr := parser.ParseAndFilterReader(stdout, allowedSeverities)
	waitErr := cmd.Wait()

	if parseErr != nil {
		fmt.Println("[ERROR] Failed to parse nuclei output:", parseErr)
		return nil, fmt.Errorf("failed to parse nuclei output: %w", parseErr)
	}

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			fmt.Println("[ERROR] Nuclei scan failed:", waitErr)
			return nil, fmt.Errorf("nuclei scan failed: %w", waitErr)
		}

		fmt.Println("[ERROR] Failed to run nuclei:", waitErr)
		return nil, fmt.Errorf("failed to run nuclei: %w", waitErr)
	}

	return findings, nil
}

func resolveNucleiPath() (string, error) {
	for _, binaryName := range localNucleiCandidates() {
		if _, err := os.Stat(binaryName); err == nil {
			absPath, err := filepath.Abs(binaryName)
			if err != nil {
				return "", fmt.Errorf("failed to resolve local %s path: %w", binaryName, err)
			}

			return absPath, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("failed to check local %s: %w", binaryName, err)
		}
	}

	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("nuclei is not installed or not available in PATH")
		}

		return "", fmt.Errorf("failed to locate nuclei: %w", err)
	}

	return nucleiPath, nil
}

func localNucleiCandidates() []string {
	if runtime.GOOS == "windows" {
		return []string{"nuclei.exe", "nuclei"}
	}

	return []string{"nuclei", "nuclei.exe"}
}
