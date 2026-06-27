package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
)

type Options struct {
	TimeoutSeconds int
	Retries        int
	Verbose        bool
	NoInteractsh   bool // when true, passes -ni flag to disable OOB interaction templates
	LogWriter      io.Writer
}

func RunNuclei(ctx context.Context, target string, allowedSeverities []string, options Options) ([]parser.NucleiFinding, error) {
	nucleiPath, err := resolveNucleiPath()
	if err != nil {
		return nil, err
	}

	if options.TimeoutSeconds <= 0 {
		options.TimeoutSeconds = 30
	}

	if options.Retries < 0 {
		options.Retries = 0
	}

	if options.LogWriter == nil {
		options.LogWriter = io.Discard
	}

	nucleiArgs := []string{
		"-target", target,
		"-jsonl",
		"-irr",
		"-severity", strings.Join(allowedSeverities, ","),
		"-timeout", fmt.Sprint(options.TimeoutSeconds),
		"-retries", fmt.Sprint(options.Retries),
		"-leave-default-ports",
	}
	if options.NoInteractsh {
		nucleiArgs = append(nucleiArgs, "-ni")
	}
	cmd := exec.CommandContext(ctx, nucleiPath, nucleiArgs...)
	cmd.Stderr = os.Stderr

	if options.Verbose {
		fmt.Fprintln(options.LogWriter, "[DEBUG] Nuclei executable:", nucleiPath)
		fmt.Fprintln(options.LogWriter, "[DEBUG] Nuclei args:", cmd.Args[1:])
		fmt.Fprintln(options.LogWriter, "[DEBUG] Full command:", strings.Join(cmd.Args, " "))
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open nuclei stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nuclei: %w", err)
	}

	findings, parseErr := parser.ParseAndFilterReader(stdout, allowedSeverities, parser.Options{
		Verbose:   options.Verbose,
		LogWriter: options.LogWriter,
	})
	waitErr := cmd.Wait()

	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse nuclei output: %w", parseErr)
	}

	// Nuclei frequently exits with a non-zero code even when findings exist
	// (e.g. runtime errors in 3 templates, warning-level issues, etc.).
	// We must NOT discard already-parsed findings in that case.
	// Only treat it as a fatal error when we have zero findings AND a non-exit error.
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			// Non-zero exit but we may still have valid findings — log as warning only.
			fmt.Fprintf(options.LogWriter, " [WARN] Nuclei exited with code %d (this is normal when templates have warnings). Findings parsed: %d\n", exitErr.ExitCode(), len(findings))
		} else {
			// Unexpected OS-level failure with no findings — surface as error.
			if len(findings) == 0 {
				return nil, fmt.Errorf("failed to run nuclei: %w", waitErr)
			}
			fmt.Fprintf(options.LogWriter, " [WARN] Nuclei runner error (non-fatal, findings preserved): %v\n", waitErr)
		}
	}

	if options.Verbose {
		fmt.Fprintf(options.LogWriter, "[DEBUG] Total findings after filter: %d\n", len(findings))
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
