package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
)

type Options struct {
	TimeoutSeconds            int
	Retries                   int
	Verbose                   bool
	NoInteractsh              bool
	Concurrency               int
	RateLimit                 int
	ParityMode                bool
	IncludeHTTP               bool
	EnableHeadless            bool
	EnableDAST                bool
	AutomaticScan             bool
	IncludeDefaultIgnoredTags []string
	Headers                   []string
	Cookie                    string
	CookieFile                string
	Tags                      []string
	ExcludeTags               []string
	Templates                 []string
	Workflows                 []string
	Types                     []string
	ShowCommand               bool
	LegacyCompatible          bool
	LogWriter                 io.Writer
	TargetsFile               string
	EnableCrawl               bool
}

type Result struct {
	Findings           []parser.NucleiFinding
	RawFindings        int
	FilteredBySeverity int
	TotalLines         int
	MalformedLines     int
	WAFBlocked         int
	Command            []string
	Stderr             string
}

var (
	nucleiFlagSupportMu sync.Mutex
	nucleiFlagSupport   = map[string]map[string]bool{}
)

func RunNuclei(ctx context.Context, target string, allowedSeverities []string, options Options) ([]parser.NucleiFinding, error) {
	result, err := RunNucleiDetailed(ctx, target, allowedSeverities, options)
	if err != nil {
		return nil, err
	}

	return result.Findings, nil
}

func RunNucleiScan(ctx context.Context, target string, allowedSeverities []string, options Options) (Result, error) {
	if options.LogWriter == nil {
		options.LogWriter = io.Discard
	}

	if !options.EnableCrawl {
		return RunNucleiDetailed(ctx, target, allowedSeverities, options)
	}

	if wafErr := checkWAFBlock(ctx, target, options.LogWriter); wafErr != nil {
		return Result{}, wafErr
	}

	crawlResult, crawlErr := CrawlTarget(ctx, target, options.Concurrency, 2, options.LogWriter, options)
	fmt.Fprintln(options.LogWriter)
	if crawlErr != nil {
		if options.Verbose {
			fmt.Fprintf(options.LogWriter, "[WARN] crawl phase failed, falling back to single-target scan: %v\n", crawlErr)
		}
		return RunNucleiDetailed(ctx, target, allowedSeverities, options)
	}

	if crawlResult.Count <= 1 {
		fmt.Fprintf(options.LogWriter, "[WARN] Crawler extracted 0 unique sub-pages (target might be protected).\n")
		if !promptForceScan(options.LogWriter) {
			return Result{}, fmt.Errorf("scan aborted by user")
		}
		return RunNucleiDetailed(ctx, target, allowedSeverities, options)
	}

	targetsFile, cleanup, err := WriteTargetsToFile(crawlResult.URLs)
	if err != nil {
		if options.Verbose {
			fmt.Fprintf(options.LogWriter, "\n[WARN] failed to write crawl targets, falling back to single-target scan: %v\n", err)
		}
		return RunNucleiDetailed(ctx, target, allowedSeverities, options)
	}
	defer cleanup()

	options.TargetsFile = targetsFile
	return RunNucleiDetailed(ctx, target, allowedSeverities, options)
}

func promptForceScan(logWriter io.Writer) bool {
	fmt.Fprintf(logWriter, "[?] Crawler yielded no new paths. Force scan the primary target URL instead? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

func RunNucleiDetailed(ctx context.Context, target string, allowedSeverities []string, options Options) (Result, error) {
	nucleiPath, err := ResolveNucleiPath()
	if err != nil {
		return Result{}, err
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

	nucleiArgs := buildStealthArgs(nucleiPath, target, allowedSeverities, options)
	command := append([]string{nucleiPath}, nucleiArgs...)

	cmd := exec.CommandContext(ctx, nucleiPath, nucleiArgs...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if options.Verbose || options.ShowCommand {
		fmt.Fprintln(options.LogWriter, "[DEBUG] Nuclei executable:", nucleiPath)
		fmt.Fprintln(options.LogWriter, "[DEBUG] Nuclei args:", cmd.Args[1:])
		fmt.Fprintln(options.LogWriter, "[DEBUG] Full command:", strings.Join(cmd.Args, " "))
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, fmt.Errorf("failed to open nuclei stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("failed to start nuclei: %w", err)
	}

	parseResult, parseErr := parser.ParseAndFilterDetailed(stdout, allowedSeverities, parser.Options{
		Verbose:   options.Verbose,
		LogWriter: options.LogWriter,
	})
	waitErr := cmd.Wait()
	result := Result{
		Findings:           parseResult.Findings,
		RawFindings:        parseResult.RawFindings,
		FilteredBySeverity: parseResult.FilteredBySeverity,
		TotalLines:         parseResult.TotalLines,
		MalformedLines:     parseResult.MalformedLines,
		WAFBlocked:         parseResult.WAFBlocked,
		Command:            command,
		Stderr:             strings.TrimSpace(stderr.String()),
	}

	if parseErr != nil {
		return Result{}, fmt.Errorf("failed to parse nuclei output: %w", parseErr)
	}

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			if options.AutomaticScan && isAutomaticScanNoTemplateError(stderr.String()) {
				fmt.Fprintln(options.LogWriter, "[WARN] Nuclei automatic scan found no matching tech-tag templates; retrying without -as")
				options.AutomaticScan = false
				return RunNucleiDetailed(ctx, target, allowedSeverities, options)
			}

			if parseResult.TotalLines > 0 && parseResult.TotalLines == parseResult.MalformedLines && len(parseResult.Findings) == 0 {
				message := strings.TrimSpace(stderr.String())
				if message == "" {
					message = "nuclei returned non-JSON output"
				}
				return Result{}, fmt.Errorf("nuclei execution failed with exit code %d: %s", exitErr.ExitCode(), message)
			}

			if options.Verbose {
				fmt.Fprintf(options.LogWriter, "[WARN] nuclei exited with code %d; findings=%d\n", exitErr.ExitCode(), len(parseResult.Findings))
				if stderr.Len() > 0 {
					fmt.Fprintf(options.LogWriter, "[WARN] nuclei stderr: %s\n", strings.TrimSpace(stderr.String()))
				}
			}
		} else {
			if len(parseResult.Findings) == 0 {
				return Result{}, fmt.Errorf("failed to run nuclei: %w", waitErr)
			}
			if options.Verbose {
				fmt.Fprintf(options.LogWriter, "[WARN] nuclei runner error (non-fatal, findings preserved): %v\n", waitErr)
			}
		}
	}

	if options.Verbose {
		fmt.Fprintf(options.LogWriter, "[DEBUG] Total findings after filter: %d\n", len(parseResult.Findings))
	}

	return result, nil
}

func isAutomaticScanNoTemplateError(stderr string) bool {
	message := strings.ToLower(stderr)
	return strings.Contains(message, "could not create automatic scan service") &&
		strings.Contains(message, "could not find any templates with tech tag")
}

func buildNucleiArgs(nucleiPath, target string, allowedSeverities []string, options Options) []string {
	args := []string{
		"-jsonl",
		"-severity", strings.Join(allowedSeverities, ","),
		"-timeout", fmt.Sprint(options.TimeoutSeconds),
		"-retries", fmt.Sprint(options.Retries),
		"-leave-default-ports",
	}

	if options.TargetsFile != "" {
		args = append(args, "-list", options.TargetsFile)
	} else {
		args = append(args, "-target", target)
	}

	if !options.ShowCommand {
		args = append(args[:3], append([]string{"-silent"}, args[3:]...)...)
	}

	if !options.ParityMode {
		args = append(args,
			"-c", fmt.Sprint(defaultInt(options.Concurrency, 150)),
			"-rl", fmt.Sprint(defaultInt(options.RateLimit, 500)),
		)
	}

	if options.IncludeHTTP {
		args = append(args, "-irr")
	} else if !options.ParityMode {
		args = append(args, "-omit-raw")
	}

	if !options.ParityMode && supportsNucleiFlag(nucleiPath, "-no-banner") {
		args = append(args, "-no-banner")
	}

	if options.NoInteractsh {
		args = append(args, "-ni")
	}

	if options.EnableHeadless {
		args = append(args, "-headless")
	}

	if options.EnableDAST {
		args = append(args, "-dast")
	}

	if options.AutomaticScan {
		args = append(args, "-as")
	}

	for _, tag := range normalizeList(options.IncludeDefaultIgnoredTags) {
		args = append(args, "-itags", tag)
	}

	for _, header := range normalizeList(options.Headers) {
		args = append(args, "-H", header)
	}

	if cookie := strings.TrimSpace(options.Cookie); cookie != "" {
		args = append(args, "-H", "Cookie: "+cookie)
	}

	if cookieFile := strings.TrimSpace(options.CookieFile); cookieFile != "" {
		args = append(args, "-H", "@"+cookieFile)
	}

	if tags := strings.Join(normalizeList(options.Tags), ","); tags != "" {
		args = append(args, "-tags", tags)
	}

	if excludeTags := strings.Join(normalizeList(options.ExcludeTags), ","); excludeTags != "" {
		args = append(args, "-etags", excludeTags)
	}

	if templates := strings.Join(normalizeList(options.Templates), ","); templates != "" {
		args = append(args, "-t", templates)
	}

	if workflows := strings.Join(normalizeList(options.Workflows), ","); workflows != "" {
		args = append(args, "-w", workflows)
	}

	if types := strings.Join(normalizeList(options.Types), ","); types != "" {
		args = append(args, "-type", types)
	}

	return args
}

func defaultInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func normalizeList(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				normalized = append(normalized, part)
			}
		}
	}

	return normalized
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

var wafBlockPatterns = []string{
	"error 1006",
	"access denied",
	"access denied.",
	"captcha",
	"just a moment",
	"checking if the site connection is secure",
	"please wait while we are checking your browser",
	"enable javascript and cookies to continue",
	"attention required",
	"ray id:",
	"cloudflare",
	"incapsula",
	"imperva",
	"akamai",
	"denied by security access",
	"security block",
	"request blocked",
	"forbidden",
}

func checkWAFBlock(ctx context.Context, target string, logWriter io.Writer) error {
	if logWriter == nil {
		logWriter = io.Discard
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	bodyStr := strings.ToLower(string(body))

	for _, pattern := range wafBlockPatterns {
		if strings.Contains(bodyStr, pattern) {
			fmt.Fprintf(logWriter, "[BLOCKED] WAF/security filter detected on %s (matched: %s)\n", target, pattern)
			return fmt.Errorf("target %s appears to be behind a WAF/security filter (matched pattern: %s)", target, pattern)
		}
	}

	lowerHeaders := strings.ToLower(strings.Join(resp.Header.Values("Server"), " "))
	cfRay := resp.Header.Get("Cf-Ray")
	if cfRay != "" {
		fmt.Fprintf(logWriter, "[BLOCKED] Cloudflare protection detected on %s (Cf-Ray: %s)\n", target, cfRay)
		return fmt.Errorf("target %s is behind Cloudflare protection", target)
	}

	_ = lowerHeaders

	return nil
}
