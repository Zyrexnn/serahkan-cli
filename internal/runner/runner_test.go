package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestLocalNucleiCandidates(t *testing.T) {
	candidates := localNucleiCandidates()
	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(candidates))
	}

	if runtime.GOOS == "windows" {
		if candidates[0] != "nuclei.exe" {
			t.Errorf("expected first candidate on Windows to be nuclei.exe, got %s", candidates[0])
		}
	} else {
		if candidates[0] != "nuclei" {
			t.Errorf("expected first candidate on non-Windows to be nuclei, got %s", candidates[0])
		}
	}
}

func TestResolveNucleiPath(t *testing.T) {
	path, err := ResolveNucleiPath()
	if err != nil {
		t.Logf("ResolveNucleiPath returned error (this is normal if nuclei is not installed and not in workspace during sandbox test run): %v", err)
	} else {
		t.Logf("ResolveNucleiPath resolved path to: %s", path)
		if path == "" {
			t.Error("expected non-empty path when error is nil")
		}
	}
}

func TestBuildNucleiArgs(t *testing.T) {
	nucleiFlagSupportMu.Lock()
	nucleiFlagSupport = map[string]map[string]bool{
		"/tmp/nuclei": {
			"-no-banner": true,
		},
		"/tmp/nuclei-no-bannerless": {
			"-no-banner": false,
		},
	}
	nucleiFlagSupportMu.Unlock()

	withBannerFlag := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 30,
		Retries:        2,
		NoInteractsh:   true,
		RawHTTP:        true,
	})
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-no-banner") {
		t.Fatalf("expected -no-banner to be included when supported")
	}
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-ni") {
		t.Fatalf("expected -ni to be included when NoInteractsh is true")
	}
	if !strings.Contains(strings.Join(withBannerFlag, " "), "-irr") {
		t.Fatalf("expected -irr to be included when RawHTTP is true")
	}

	withoutBannerFlag := buildNucleiArgs("/tmp/nuclei-no-bannerless", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 30,
		Retries:        2,
	})
	if strings.Contains(strings.Join(withoutBannerFlag, " "), "-no-banner") {
		t.Fatalf("expected -no-banner to be omitted when unsupported")
	}
	if strings.Contains(strings.Join(withoutBannerFlag, " "), "-irr") {
		t.Fatalf("expected -irr to be omitted by default")
	}
	if !strings.Contains(strings.Join(withoutBannerFlag, " "), "-omit-raw") {
		t.Fatalf("expected -omit-raw to be included by default")
	}

	webArgs := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"info", "low", "medium", "high", "critical"}, Options{
		TimeoutSeconds: 30,
		Retries:        1,
		Concurrency:    300,
		RateLimit:      800,
		EnableHeadless: true,
		EnableDAST:     true,
		TechDetect:     true,
		ForceTags:      []string{"fuzz"},
		Headers:        []string{"Authorization: Bearer token"},
		Cookie:         "sid=abc",
		Tags:           []string{"xss,sqli"},
		ExcludeTags:    []string{"dos"},
		Templates:      []string{"http/exposures"},
		Workflows:      []string{"workflows/test.yaml"},
		Protocols:      []string{"http,headless"},
	})
	webJoined := strings.Join(webArgs, " ")
	expectedParts := []string{
		"-headless",
		"-dast",
		"-as",
		"-c 300",
		"-rl 800",
		"-itags fuzz",
		"-H Authorization: Bearer token",
		"-H Cookie: sid=abc",
		"-tags xss,sqli",
		"-etags dos",
		"-t http/exposures",
		"-w workflows/test.yaml",
		"-type http,headless",
	}
	for _, expected := range expectedParts {
		if !strings.Contains(webJoined, expected) {
			t.Fatalf("expected args to contain %q, got %q", expected, webJoined)
		}
	}

	showCmdArgs := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
		ShowCommand:    true,
	})
	showCmdJoined := strings.Join(showCmdArgs, " ")
	if strings.Contains(showCmdJoined, "-silent") {
		t.Fatalf("expected -silent to be omitted when ShowCommand is true, got %q", showCmdJoined)
	}

	normalArgs := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
		ShowCommand:    false,
	})
	normalJoined := strings.Join(normalArgs, " ")
	if strings.Contains(normalJoined, "-silent") {
		t.Fatalf("expected -silent to be omitted in normal args, got %q", normalJoined)
	}
}

func TestIsAutomaticScanNoTemplateError(t *testing.T) {
	stderr := "[FTL] Could not run nuclei: could not create automatic scan service: could not find any templates with tech tag"
	if !isAutomaticScanNoTemplateError(stderr) {
		t.Fatalf("expected automatic scan no-template error to be detected")
	}

	if isAutomaticScanNoTemplateError("[FTL] unrelated nuclei failure") {
		t.Fatalf("expected unrelated error to be ignored")
	}
}

func TestRandomUserAgent(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		ua := randomUserAgent()
		if ua == "" {
			t.Fatal("expected non-empty user agent")
		}
		if strings.Contains(ua, "Nuclei") {
			t.Fatalf("user agent must not contain Nuclei fingerprint, got: %s", ua)
		}
		seen[ua] = true
	}
	if len(seen) < 5 {
		t.Fatalf("expected at least 5 distinct user agents in 50 iterations, got %d", len(seen))
	}
}

func TestJitterValue(t *testing.T) {
	for i := 0; i < 100; i++ {
		result := jitterValue(300, -15, 15)
		if result < 255 || result > 345 {
			t.Fatalf("jitterValue(300, -15, 15) = %d, expected between 255 and 345", result)
		}
	}

	if jitterValue(0, -15, 15) != 0 {
		t.Fatal("expected zero input to return zero")
	}
	if jitterValue(-5, -15, 15) != -5 {
		t.Fatal("expected negative input to return unchanged")
	}
}

func TestApplyStealthHeaders(t *testing.T) {
	options := Options{
		Headers: []string{"Authorization: Bearer token"},
	}
	applyStealthHeaders(&options)

	if len(options.Headers) < 2 {
		t.Fatalf("expected at least 2 headers after stealth apply, got %d", len(options.Headers))
	}

	uaHeader := options.Headers[0]
	if !strings.HasPrefix(uaHeader, "User-Agent: ") {
		t.Fatalf("expected first header to be User-Agent, got: %s", uaHeader)
	}
	if strings.Contains(uaHeader, "Nuclei") {
		t.Fatalf("User-Agent must not contain Nuclei, got: %s", uaHeader)
	}
	if !strings.Contains(uaHeader, "Mozilla/5.0") {
		t.Fatalf("expected modern browser User-Agent, got: %s", uaHeader)
	}

	existingHeader := options.Headers[1]
	if existingHeader != "Authorization: Bearer token" {
		t.Fatalf("expected existing header to be preserved, got: %s", existingHeader)
	}
}

func TestApplyAggressiveJitter(t *testing.T) {
	options := Options{
		Concurrency: 300,
		RateLimit:   800,
	}

	seen := make(map[int]bool)
	for i := 0; i < 50; i++ {
		opts := options
		applyAggressiveJitter(&opts)
		seen[opts.Concurrency] = true
		if opts.Concurrency < 255 || opts.Concurrency > 345 {
			t.Fatalf("concurrency jitter out of range: %d", opts.Concurrency)
		}
		if opts.RateLimit < 720 || opts.RateLimit > 880 {
			t.Fatalf("rate limit jitter out of range: %d", opts.RateLimit)
		}
	}

	if len(seen) < 3 {
		t.Fatalf("expected jittered concurrency to vary, got %d distinct values", len(seen))
	}
}

func TestApplyAggressiveJitterSkipsZeroValues(t *testing.T) {
	options := Options{
		Concurrency: 0,
		RateLimit:   0,
	}
	applyAggressiveJitter(&options)
	if options.Concurrency != 0 {
		t.Fatalf("expected zero concurrency to remain unchanged, got %d", options.Concurrency)
	}
	if options.RateLimit != 0 {
		t.Fatalf("expected zero rate limit to remain unchanged, got %d", options.RateLimit)
	}
}

func TestBuildStealthArgs(t *testing.T) {
	nucleiFlagSupportMu.Lock()
	nucleiFlagSupport["/tmp/nuclei"] = map[string]bool{"-no-banner": true}
	nucleiFlagSupportMu.Unlock()

	args := buildStealthArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
	})

	joined := strings.Join(args, " ")

	if strings.Contains(joined, "-silent") {
		t.Fatal("expected -silent to be omitted in stealth args")
	}

	uaFound := false
	for i, arg := range args {
		if arg == "-H" && i+1 < len(args) && strings.HasPrefix(args[i+1], "User-Agent: ") {
			uaFound = true
			if strings.Contains(args[i+1], "Nuclei") {
				t.Fatalf("stealth User-Agent must not contain Nuclei, got: %s", args[i+1])
			}
			break
		}
	}
	if !uaFound {
		t.Fatal("expected User-Agent header in stealth args")
	}
}

func TestBuildStealthArgsBrutalAppliesJitter(t *testing.T) {
	nucleiFlagSupportMu.Lock()
	nucleiFlagSupport["/tmp/nuclei"] = map[string]bool{"-no-banner": true}
	nucleiFlagSupportMu.Unlock()

	args := buildStealthArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
		Concurrency:    300,
		RateLimit:      800,
		EnableDAST:     true,
	})

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-c ") {
		t.Fatal("expected -c in brutal stealth args")
	}
	if !strings.Contains(joined, "-rl ") {
		t.Fatal("expected -rl in brutal stealth args")
	}
	if strings.Contains(joined, "(+jitter~") {
		t.Fatal("expected stealth args to keep nuclei flag values numeric")
	}
}

func TestHasNucleiFingerprint(t *testing.T) {
	if !hasNucleiFingerprint([]string{"-target", "http://x.com", "-H", "User-Agent: Nuclei/1.0"}) {
		t.Fatal("expected nuclei fingerprint detection")
	}
	if hasNucleiFingerprint([]string{"-target", "http://x.com", "-silent"}) {
		t.Fatal("expected no false positive for normal args")
	}
}

func TestUserAgentListCoverage(t *testing.T) {
	browsers := map[string]bool{
		"Chrome":  false,
		"Safari":  false,
		"Firefox": false,
		"Edg":     false,
	}
	for _, ua := range stealthUserAgents {
		if strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Edg") {
			browsers["Chrome"] = true
		}
		if strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome") {
			browsers["Safari"] = true
		}
		if strings.Contains(ua, "Firefox") {
			browsers["Firefox"] = true
		}
		if strings.Contains(ua, "Edg") {
			browsers["Edg"] = true
		}
	}
	for browser, found := range browsers {
		if !found {
			t.Fatalf("expected User-Agent list to contain %s", browser)
		}
	}

	hasWindows := false
	hasMacOS := false
	hasLinux := false
	hasIOS := false
	for _, ua := range stealthUserAgents {
		if strings.Contains(ua, "Windows NT 10.0") {
			hasWindows = true
		}
		if strings.Contains(ua, "Macintosh; Intel Mac OS X") {
			hasMacOS = true
		}
		if strings.Contains(ua, "X11; Linux") || strings.Contains(ua, "X11; Ubuntu") {
			hasLinux = true
		}
		if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
			hasIOS = true
		}
	}
	if !hasWindows {
		t.Fatal("expected Windows User-Agent")
	}
	if !hasMacOS {
		t.Fatal("expected macOS User-Agent")
	}
	if !hasLinux {
		t.Fatal("expected Linux User-Agent")
	}
	if !hasIOS {
		t.Fatal("expected iOS User-Agent")
	}
}

func TestStealthHeadersPreserveOrder(t *testing.T) {
	for i := 0; i < 20; i++ {
		options := Options{
			Headers: []string{"X-Custom: value", "Authorization: Bearer tok"},
		}
		applyStealthHeaders(&options)

		if !strings.HasPrefix(options.Headers[0], "User-Agent: ") {
			t.Fatalf("expected User-Agent as first header, got: %s", options.Headers[0])
		}
		if options.Headers[1] != "X-Custom: value" {
			t.Fatalf("expected first custom header preserved at index 1, got: %s", options.Headers[1])
		}
		if options.Headers[2] != "Authorization: Bearer tok" {
			t.Fatalf("expected second custom header preserved at index 2, got: %s", options.Headers[2])
		}
	}
}

func TestWriteTargetsToFile(t *testing.T) {
	urls := []string{"https://example.com/", "https://example.com/login", "https://example.com/api"}
	filePath, cleanup, err := WriteTargetsToFile(urls)
	if err != nil {
		t.Fatalf("WriteTargetsToFile() error = %v", err)
	}
	defer cleanup()

	if filePath == "" {
		t.Fatal("expected non-empty file path")
	}

	data, readErr := os.ReadFile(filePath)
	if readErr != nil {
		t.Fatalf("failed to read targets file: %v", readErr)
	}

	content := string(data)
	for _, u := range urls {
		if !strings.Contains(content, u+"\n") {
			t.Fatalf("expected URL %q in targets file, got content:\n%s", u, content)
		}
	}
}

func TestWriteTargetsToFileEmpty(t *testing.T) {
	filePath, cleanup, err := WriteTargetsToFile([]string{})
	if err != nil {
		t.Fatalf("WriteTargetsToFile() error = %v", err)
	}
	defer cleanup()

	if filePath == "" {
		t.Fatal("expected non-empty file path for empty input")
	}

	data, readErr := os.ReadFile(filePath)
	if readErr != nil {
		t.Fatalf("failed to read targets file: %v", readErr)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty file for empty input, got %d bytes", len(data))
	}
}

func TestBuildNucleiArgsWithTargetsFile(t *testing.T) {
	nucleiFlagSupportMu.Lock()
	nucleiFlagSupport["/tmp/nuclei"] = map[string]bool{"-no-banner": true}
	nucleiFlagSupportMu.Unlock()

	args := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
		TargetsFile:    "/tmp/crawl-targets.txt",
	})

	targetFlagFound := false
	for i, arg := range args {
		if arg == "-target" {
			targetFlagFound = true
			_ = i
			break
		}
	}

	if targetFlagFound {
		t.Fatalf("expected -target flag to be omitted when TargetsFile is set")
	}

	listFound := false
	for i, arg := range args {
		if arg == "-list" && i+1 < len(args) && args[i+1] == "/tmp/crawl-targets.txt" {
			listFound = true
			break
		}
	}
	if !listFound {
		t.Fatalf("expected -list with targets file path, got: %s", strings.Join(args, " "))
	}
}

func TestBuildNucleiArgsWithProxy(t *testing.T) {
	nucleiFlagSupportMu.Lock()
	nucleiFlagSupport["/tmp/nuclei"] = map[string]bool{"-no-banner": true}
	nucleiFlagSupportMu.Unlock()

	args := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
		Proxy:          "http://127.0.0.1:8080",
	})

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-p http://127.0.0.1:8080") {
		t.Fatalf("expected proxy flag -p in args, got: %s", joined)
	}

	argsNoProxy := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
	})
	noJoined := strings.Join(argsNoProxy, " ")
	if strings.Contains(noJoined, "-p ") {
		t.Fatalf("expected no proxy flag when proxy is empty, got: %s", noJoined)
	}
}

func TestBuildNucleiArgsWithoutTargetsFile(t *testing.T) {
	nucleiFlagSupportMu.Lock()
	nucleiFlagSupport["/tmp/nuclei"] = map[string]bool{"-no-banner": true}
	nucleiFlagSupportMu.Unlock()

	args := buildNucleiArgs("/tmp/nuclei", "https://example.com", []string{"high"}, Options{
		TimeoutSeconds: 10,
		Retries:        0,
	})

	listFound := false
	for _, arg := range args {
		if arg == "-list" {
			listFound = true
			break
		}
	}
	if listFound {
		t.Fatal("expected -list to be omitted when TargetsFile is empty")
	}

	targetFound := false
	for i, arg := range args {
		if arg == "-target" && i+1 < len(args) && args[i+1] == "https://example.com" {
			targetFound = true
			break
		}
	}
	if !targetFound {
		t.Fatalf("expected -target with original URL, got: %s", strings.Join(args, " "))
	}
}

func TestCrawlTargetContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := CrawlTarget(ctx, "http://127.0.0.1:1", 10, 1, nil)
	if err == nil && result.Count == 0 {
		t.Log("crawl returned empty results for cancelled context (expected)")
	}
}

func TestCrawlTargetInvalidURL(t *testing.T) {
	_, err := CrawlTarget(context.Background(), "://invalid", 10, 1, nil)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestBuildCrawlHeadersContainsUA(t *testing.T) {
	headers := buildCrawlHeaders(Options{})
	uaFound := false
	for _, h := range headers {
		if strings.HasPrefix(h, "User-Agent: ") {
			uaFound = true
			uaVal := strings.TrimPrefix(h, "User-Agent: ")
			if strings.Contains(uaVal, "Nuclei") {
				t.Fatalf("crawl User-Agent must not contain Nuclei, got: %s", uaVal)
			}
			if !strings.Contains(uaVal, "Mozilla/5.0") {
				t.Fatalf("expected modern browser User-Agent, got: %s", uaVal)
			}
			break
		}
	}
	if !uaFound {
		t.Fatal("expected User-Agent header in crawl headers")
	}
}

func TestBuildCrawlHeadersIncludesBrowserHeaders(t *testing.T) {
	headers := buildCrawlHeaders(Options{})
	joined := strings.Join(headers, "\n")

	expectedHeaders := []string{
		"Accept-Language:",
		"Accept:",
		"Sec-Ch-Ua:",
		"Sec-Fetch-Dest:",
		"Sec-Fetch-Mode:",
		"Sec-Fetch-Site:",
		"Upgrade-Insecure-Requests:",
		"Cache-Control:",
	}
	for _, expected := range expectedHeaders {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected crawl headers to contain %q, got headers:\n%s", expected, joined)
		}
	}
}

func TestBuildCrawlHeadersInjectsCookie(t *testing.T) {
	headers := buildCrawlHeaders(Options{
		Cookie: "session=abc123; token=xyz",
	})

	cookieFound := false
	for _, h := range headers {
		if strings.HasPrefix(h, "Cookie: ") {
			cookieFound = true
			cookieVal := strings.TrimPrefix(h, "Cookie: ")
			if cookieVal != "session=abc123; token=xyz" {
				t.Fatalf("expected cookie value 'session=abc123; token=xyz', got: %s", cookieVal)
			}
			break
		}
	}
	if !cookieFound {
		t.Fatal("expected Cookie header in crawl headers when cookie is set")
	}
}

func TestBuildCrawlHeadersNoCookieWhenEmpty(t *testing.T) {
	headers := buildCrawlHeaders(Options{})
	for _, h := range headers {
		if strings.HasPrefix(h, "Cookie:") {
			t.Fatalf("expected no Cookie header when cookie is empty, got: %s", h)
		}
	}
}

func TestBuildCrawlHeadersPreservesCustomHeaders(t *testing.T) {
	headers := buildCrawlHeaders(Options{
		Headers: []string{"Authorization: Bearer token", "X-Custom: value"},
	})

	authFound := false
	customFound := false
	for _, h := range headers {
		if h == "Authorization: Bearer token" {
			authFound = true
		}
		if h == "X-Custom: value" {
			customFound = true
		}
	}
	if !authFound {
		t.Fatal("expected Authorization header to be preserved")
	}
	if !customFound {
		t.Fatal("expected X-Custom header to be preserved")
	}
}

func TestBuildCrawlHeadersStripsDuplicateUA(t *testing.T) {
	headers := buildCrawlHeaders(Options{
		Headers: []string{"User-Agent: custom-agent/1.0"},
	})

	uaCount := 0
	for _, h := range headers {
		if strings.HasPrefix(h, "User-Agent: ") {
			uaCount++
		}
	}
	if uaCount != 1 {
		t.Fatalf("expected exactly 1 User-Agent header (the randomized one), got %d", uaCount)
	}
}

func TestBuildCrawlHeadersStripsDuplicateCookie(t *testing.T) {
	headers := buildCrawlHeaders(Options{
		Cookie:  "session=abc",
		Headers: []string{"Cookie: other=xyz"},
	})

	cookieCount := 0
	for _, h := range headers {
		if strings.HasPrefix(h, "Cookie: ") {
			cookieCount++
		}
	}
	if cookieCount != 1 {
		t.Fatalf("expected exactly 1 Cookie header (from options.Cookie), got %d", cookieCount)
	}
}

func TestCrawlTargetWithOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := CrawlTarget(ctx, "http://127.0.0.1:1", 10, 1, nil, Options{
		Cookie:  "session=test123",
		Headers: []string{"Authorization: Bearer token"},
	})
	if err == nil {
		t.Log("crawl returned without error for cancelled context")
	}
}

func TestWAFBlockPatternsNotEmpty(t *testing.T) {
	if len(wafBlockPatterns) == 0 {
		t.Fatal("expected wafBlockPatterns to be non-empty")
	}
}

func TestCheckWAFBlockAllowsCloudflareCDN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Ray", "12345-abc")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello")
	}))
	defer server.Close()

	err := checkWAFBlock(context.Background(), server.URL, "", nil)
	if err != nil {
		t.Fatalf("expected nil error for Cloudflare CDN header, got: %v", err)
	}
}

func TestCheckWAFBlockDetectsPatterns(t *testing.T) {
	patternTests := []struct {
		name     string
		body     string
		expected string
	}{
		{"Error 1006", "Error 1006 access denied", "error 1006"},
		{"captcha", "<title>captcha challenge</title>", "captcha"},
		{"Just a moment", "Just a moment while we verify", "just a moment"},
		{"Access denied", "Access denied. Your IP has been blocked", "access denied"},
		{"Attention required", "Attention Required! | Cloudflare", "attention required"},
		{"Forbidden", "<h1>403 Forbidden</h1><p>You don't have permission to access this server.</p>", "forbidden"},
	}

	for _, tt := range patternTests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, tt.body)
			}))
			defer server.Close()

			err := checkWAFBlock(context.Background(), server.URL, "", nil)
			if err == nil {
				t.Fatalf("expected error for pattern %q, got nil", tt.name)
			}
			if !strings.Contains(err.Error(), tt.expected) {
				t.Fatalf("expected error to contain %q, got: %s", tt.expected, err.Error())
			}
		})
	}
}

func TestCheckWAFBlockNoDetectionOnCleanResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><head><title>My App</title></head><body>Hello World</body></html>")
	}))
	defer server.Close()

	err := checkWAFBlock(context.Background(), server.URL, "", nil)
	if err != nil {
		t.Fatalf("expected nil error for clean response, got: %v", err)
	}
}

func TestCheckWAFBlockHandlesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := checkWAFBlock(ctx, "http://127.0.0.1:1", "", nil)
	if err != nil {
		t.Fatalf("expected nil error for cancelled context (connection refused), got: %v", err)
	}
}

func TestValidateProxyEmpty(t *testing.T) {
	if err := validateProxy(""); err != nil {
		t.Fatalf("expected nil for empty proxy, got: %v", err)
	}
}

func TestValidateProxyUnreachable(t *testing.T) {
	err := validateProxy("http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for unreachable proxy, got nil")
	}
	if !strings.Contains(err.Error(), "proxy") || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected error to mention proxy and unreachable, got: %v", err)
	}
}

func TestValidateProxySocks5(t *testing.T) {
	err := validateProxy("socks5://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for unreachable socks5 proxy, got nil")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected unreachable error for socks5, got: %v", err)
	}
}

func TestValidateProxyWithPath(t *testing.T) {
	err := validateProxy("http://127.0.0.1:1/some/path")
	if err == nil {
		t.Fatal("expected error for unreachable proxy with path, got nil")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected unreachable error, got: %v", err)
	}
}
