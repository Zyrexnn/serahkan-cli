package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
	"github.com/Zyrexnn/serahkan-cli/internal/style"
)

type Options struct {
	TimeoutSeconds    int
	Retries           int
	Verbose           bool
	NoInteractsh      bool
	Concurrency       int
	RateLimit         int
	RawHTTP           bool
	EnableHeadless    bool
	EnableDAST        bool
	TechDetect        bool
	ForceTags         []string
	Headers           []string
	Cookie            string
	CookieFile        string
	LoginURL          string
	LoginData         string
	LoginThreshold    int
	LoginCookieOutput string
	Tags              []string
	ExcludeTags       []string
	Templates         []string
	Workflows         []string
	Protocols         []string
	ShowCommand       bool
	LogWriter         io.Writer
	TargetsFile       string
	EnableCrawl       bool
	SkipWAFCheck      bool
	StrictWAFCheck    bool
	Proxy             string
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

	if !options.EnableCrawl || options.TargetsFile != "" {
		return RunNucleiDetailed(ctx, target, allowedSeverities, options)
	}

	if !options.SkipWAFCheck {
		if wafErr := checkWAFBlock(ctx, target, options.LogWriter); wafErr != nil {
			if options.StrictWAFCheck {
				return Result{}, wafErr
			}
			fmt.Fprintf(options.LogWriter, "[WARN] WAF/security precheck warning: %v; continuing scan\n", wafErr)
		}
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
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintln(logWriter)
		return false
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

func validateProxy(proxy string) error {
	if proxy == "" {
		return nil
	}

	hostPort := proxy
	for _, prefix := range []string{"http://", "https://", "socks5://", "socks5h://"} {
		if strings.HasPrefix(strings.ToLower(hostPort), prefix) {
			hostPort = hostPort[len(prefix):]
			break
		}
	}

	if idx := strings.Index(hostPort, "/"); idx >= 0 {
		hostPort = hostPort[:idx]
	}

	conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	if err != nil {
		return fmt.Errorf("proxy %q unreachable: %w", proxy, err)
	}
	conn.Close()
	return nil
}

func renderNucleiStderr(logWriter io.Writer, raw string, verbose bool) {
	if logWriter == nil || strings.TrimSpace(raw) == "" {
		return
	}

	inBanner := false
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.Contains(trimmed, "projectdiscovery.io") {
			inBanner = false
			continue
		}
		if strings.Contains(trimmed, "____  __") || strings.HasPrefix(trimmed, "__     _") || inBanner {
			inBanner = true
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "[FTL]") || strings.HasPrefix(trimmed, "[ERR]"):
			fmt.Fprintf(logWriter, "%s %s\n", style.TagFail, trimmed)
		case strings.HasPrefix(trimmed, "[WRN]") || strings.HasPrefix(trimmed, "[WARNING]"):
			fmt.Fprintf(logWriter, "%s %s\n", style.TagWarn, trimmed)
		case strings.HasPrefix(trimmed, "[INF]"):
			if verbose {
				fmt.Fprintf(logWriter, "%s %s\n", style.TagDebug, trimmed)
			}
		default:
			if verbose {
				fmt.Fprintf(logWriter, "%s %s\n", style.TagDebug, trimmed)
			}
		}
	}
}

func RunNucleiDetailed(ctx context.Context, target string, allowedSeverities []string, options Options) (Result, error) {
	nucleiPath, err := ResolveNucleiPath()
	if err != nil {
		return Result{}, err
	}

	if options.TimeoutSeconds <= 0 {
		options.TimeoutSeconds = 10
	}

	if options.Retries < 0 {
		options.Retries = 2
	}

	if options.LogWriter == nil {
		options.LogWriter = io.Discard
	}

	if proxy := strings.TrimSpace(options.Proxy); proxy != "" {
		if err := validateProxy(proxy); err != nil {
			return Result{}, err
		}
	}

	nucleiArgs := buildStealthArgs(nucleiPath, target, allowedSeverities, options)
	command := append([]string{nucleiPath}, nucleiArgs...)

	cmd := exec.CommandContext(ctx, nucleiPath, nucleiArgs...)

	if options.Verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG-STEP-2] Biner Nuclei dipanggil: %s\n", nucleiPath)
		for i, a := range nucleiArgs {
			fmt.Fprintf(os.Stderr, "[DEBUG-ARG %d] %q\n", i, a)
		}
		fmt.Fprintf(os.Stderr, "[DEBUG-CMD-STRING] %s\n", cmd.String())
	}
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

	renderNucleiStderr(options.LogWriter, stderr.String(), options.Verbose)

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
			if options.TechDetect && isAutomaticScanNoTemplateError(stderr.String()) {
				fmt.Fprintln(options.LogWriter, "[WARN] Nuclei automatic scan found no matching tech-tag templates; retrying without -as")
				options.TechDetect = false
				return RunNucleiDetailed(ctx, target, allowedSeverities, options)
			}

			if parseResult.TotalLines > 0 && parseResult.TotalLines == parseResult.MalformedLines && len(parseResult.Findings) == 0 {
				message := strings.TrimSpace(stderr.String())
				if message == "" {
					message = "nuclei returned non-JSON output"
				}
				return Result{}, fmt.Errorf("nuclei execution failed with exit code %d: %s", exitErr.ExitCode(), message)
			}

			if len(parseResult.Findings) == 0 {
				message := strings.TrimSpace(stderr.String())
				if message == "" {
					message = fmt.Sprintf("nuclei exited with code %d and produced no findings", exitErr.ExitCode())
				}
				return Result{}, fmt.Errorf("nuclei execution failed (exit %d): %s", exitErr.ExitCode(), message)
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
	}

	if options.TargetsFile != "" {
		args = append(args, "-list", options.TargetsFile)
	} else {
		args = append(args, "-target", target)
	}

	args = append(args,
		"-c", fmt.Sprint(options.Concurrency),
		"-rl", fmt.Sprint(options.RateLimit),
	)

	if options.RawHTTP {
		args = append(args, "-irr")
	} else {
		args = append(args, "-omit-raw")
	}

	if supportsNucleiFlag(nucleiPath, "-no-banner") {
		args = append(args, "-no-banner")
	}

	if supportsNucleiFlag(nucleiPath, "-random-agent") {
		args = append(args, "-random-agent")
	}

	if supportsNucleiFlag(nucleiPath, "-tls-impersonate") {
		args = append(args, "-tls-impersonate")
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

	if options.TechDetect {
		args = append(args, "-as")
	}

	for _, tag := range normalizeList(options.ForceTags) {
		args = append(args, "-itags", tag)
	}

	for _, header := range options.Headers {
		args = append(args, "-H", header)
	}

	if cookie := strings.TrimSpace(options.Cookie); cookie != "" {
		args = append(args, "-H", "Cookie: "+cookie)
	}

	if loginCookie := strings.TrimSpace(options.LoginCookieOutput); loginCookie != "" && strings.TrimSpace(options.Cookie) == "" {
		args = append(args, "-H", "Cookie: "+loginCookie)
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

	if protocols := strings.Join(normalizeList(options.Protocols), ","); protocols != "" {
		args = append(args, "-type", protocols)
	}

	if proxy := strings.TrimSpace(options.Proxy); proxy != "" {
		args = append(args, "-p", proxy)
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
			return "", nucleiMissingError()
		}

		return "", fmt.Errorf("failed to locate nuclei: %w", err)
	}

	return nucleiPath, nil
}

func nucleiMissingError() error {
	base := "nuclei binary not found (checked ./nuclei.exe and PATH)"

	if runtime.GOOS == "windows" {
		root, _ := os.Getwd()
		base += fmt.Sprintf("\n\nWindows: Windows Defender may quarantine Nuclei as HackTool/PUA, so it disappears after download."+
			"\n  Whitelist this folder first (run as Administrator):"+
			"\n    Add-MpPreference -ExclusionPath \"%s\""+
			"\n  Then place nuclei.exe next to serahkan.exe, or run:"+
			"\n    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", root)
	} else {
		base += "\n\nInstall: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" +
			"\nOr place the nuclei binary in your PATH."
	}

	return fmt.Errorf("%s", base)
}

func ResolveNucleiVersion() (string, error) {
	nucleiPath, err := ResolveNucleiPath()
	if err != nil {
		return "", err
	}

	cmd := exec.Command(nucleiPath, "-version")
	stderr, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to determine nuclei version: %w", err)
	}

	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.Contains(line, "Nuclei Engine Version:") {
			parts := strings.Split(line, "v")
			if len(parts) >= 2 {
				version := strings.TrimSpace(strings.Split(parts[1], " ")[0])
				if version != "" {
					return version, nil
				}
			}
		}
	}

	return "", fmt.Errorf("unable to parse nuclei version from output: %s", string(stderr))
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
	"denied by security access",
	"security block",
	"request blocked",
	"forbidden",
}

var wafVendorHeaders = []string{"cloudflare", "imperva", "incapsula", "akamai", "waf"}

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

	if resp.StatusCode == 0 {
		return nil
	}

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
	for _, vendor := range wafVendorHeaders {
		if strings.Contains(lowerHeaders, vendor) {
			fmt.Fprintf(logWriter, "[WARN] WAF/CDN server header detected on %s (server: %s)\n", target, lowerHeaders)
			return nil
		}
	}

	return nil
}
