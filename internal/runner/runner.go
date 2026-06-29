package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
)

type Options struct {
	TimeoutSeconds int
	Retries        int
	Verbose        bool
	NoInteractsh   bool
	LogWriter      io.Writer
}

var (
	nucleiFlagSupportMu sync.Mutex
	nucleiFlagSupport   = map[string]map[string]bool{}
)

func RunNuclei(ctx context.Context, target string, allowedSeverities []string, options Options) ([]parser.NucleiFinding, error) {
	nucleiPath, err := ResolveNucleiPath()
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

	nucleiArgs := buildNucleiArgs(nucleiPath, target, allowedSeverities, options)

	cmd := exec.CommandContext(ctx, nucleiPath, nucleiArgs...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

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

	parseResult, parseErr := parser.ParseAndFilterDetailed(stdout, allowedSeverities, parser.Options{
		Verbose:   options.Verbose,
		LogWriter: options.LogWriter,
	})
	waitErr := cmd.Wait()

	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse nuclei output: %w", parseErr)
	}

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			if parseResult.TotalLines > 0 && parseResult.TotalLines == parseResult.MalformedLines && len(parseResult.Findings) == 0 {
				message := strings.TrimSpace(stderr.String())
				if message == "" {
					message = "nuclei returned non-JSON output"
				}
				return nil, fmt.Errorf("nuclei execution failed with exit code %d: %s", exitErr.ExitCode(), message)
			}

			if options.Verbose {
				fmt.Fprintf(options.LogWriter, "[WARN] nuclei exited with code %d; findings=%d\n", exitErr.ExitCode(), len(parseResult.Findings))
				if stderr.Len() > 0 {
					fmt.Fprintf(options.LogWriter, "[WARN] nuclei stderr: %s\n", strings.TrimSpace(stderr.String()))
				}
			}
		} else {
			if len(parseResult.Findings) == 0 {
				return nil, fmt.Errorf("failed to run nuclei: %w", waitErr)
			}
			if options.Verbose {
				fmt.Fprintf(options.LogWriter, "[WARN] nuclei runner error (non-fatal, findings preserved): %v\n", waitErr)
			}
		}
	}

	if options.Verbose {
		fmt.Fprintf(options.LogWriter, "[DEBUG] Total findings after filter: %d\n", len(parseResult.Findings))
	}

	return parseResult.Findings, nil
}

func buildNucleiArgs(nucleiPath, target string, allowedSeverities []string, options Options) []string {
	args := []string{
		"-target", target,
		"-jsonl",
		"-irr",
		"-silent",
		"-severity", strings.Join(allowedSeverities, ","),
		"-timeout", fmt.Sprint(options.TimeoutSeconds),
		"-retries", fmt.Sprint(options.Retries),
		"-c", "150",
		"-rl", "500",
		"-leave-default-ports",
	}

	if supportsNucleiFlag(nucleiPath, "-no-banner") {
		args = append(args, "-no-banner")
	}

	if options.NoInteractsh {
		args = append(args, "-ni")
	}

	return args
}

func supportsNucleiFlag(nucleiPath, flag string) bool {
	nucleiFlagSupportMu.Lock()
	if support, ok := nucleiFlagSupport[nucleiPath]; ok {
		if value, ok := support[flag]; ok {
			nucleiFlagSupportMu.Unlock()
			return value
		}
	}
	nucleiFlagSupportMu.Unlock()

	cmd := exec.Command(nucleiPath, "-h")
	output, err := cmd.CombinedOutput()
	supported := err == nil && strings.Contains(string(output), flag)

	nucleiFlagSupportMu.Lock()
	if _, ok := nucleiFlagSupport[nucleiPath]; !ok {
		nucleiFlagSupport[nucleiPath] = map[string]bool{}
	}
	nucleiFlagSupport[nucleiPath][flag] = supported
	nucleiFlagSupportMu.Unlock()

	return supported
}

func ResolveNucleiPath() (string, error) {
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
