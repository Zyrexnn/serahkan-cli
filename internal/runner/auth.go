package runner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type LoginResult struct {
	Cookies    string
	Success    bool
	StatusCode int
}

func AttemptLogin(ctx context.Context, loginURL, loginData string, threshold int, logWriter io.Writer) (LoginResult, error) {
	if logWriter == nil {
		logWriter = io.Discard
	}

	loginURL = strings.TrimSpace(loginURL)
	loginData = strings.TrimSpace(loginData)

	if loginURL == "" || loginData == "" {
		return LoginResult{}, fmt.Errorf("login-url and login-data are required for authentication")
	}

	if detectedURL, err := DetectLoginFormAction(ctx, loginURL); err == nil && detectedURL != "" && detectedURL != loginURL {
		fmt.Fprintf(logWriter, "[AUTH] detected login form action %s\n", detectedURL)
		loginURL = detectedURL
	}

	fmt.Fprintf(logWriter, "[AUTH] attempting login to %s\n", loginURL)

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	body := strings.NewReader(loginData)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, loginURL, body)
	if err != nil {
		return LoginResult{}, fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", randomUserAgent())

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return LoginResult{}, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	result := LoginResult{
		StatusCode: resp.StatusCode,
	}

	cookies := resp.Cookies()
	if len(cookies) > 0 {
		var cookieParts []string
		for _, c := range cookies {
			cookieParts = append(cookieParts, c.Name+"="+c.Value)
		}
		result.Cookies = strings.Join(cookieParts, "; ")
	}

	if threshold > 0 {
		result.Success = resp.StatusCode == threshold
	} else {
		result.Success = resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusMovedPermanently
	}

	if result.Success {
		fmt.Fprintf(logWriter, "[AUTH] login successful (status=%d, cookies=%d)\n", resp.StatusCode, len(cookies))
	} else {
		fmt.Fprintf(logWriter, "[AUTH] login returned status %d\n", resp.StatusCode)
	}

	return result, nil
}

func DetectLoginFormAction(ctx context.Context, pageURL string) (string, error) {
	pageURL = strings.TrimSpace(pageURL)
	if pageURL == "" {
		return "", nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, pageURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", randomUserAgent())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", err
	}

	action := extractFormAction(string(body))
	if action == "" {
		return "", nil
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return "", err
	}
	actionURL, err := url.Parse(action)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(actionURL).String(), nil
}

func IsLoginPage(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	return strings.Contains(path, "/login") ||
		strings.Contains(path, "/signin") ||
		strings.Contains(path, "/sign-in") ||
		strings.Contains(path, "/logon") ||
		strings.Contains(path, "/auth") && !strings.Contains(path, "/logout") && !strings.Contains(path, "/unauth")
}

func extractFormAction(html string) string {
	lower := strings.ToLower(html)
	idx := strings.Index(lower, "<form")
	if idx < 0 {
		return ""
	}
	form := html[idx:]
	lowerForm := lower[idx:]
	endForm := strings.Index(lowerForm, ">")
	if endForm >= 0 {
		form = form[:endForm]
		lowerForm = lowerForm[:endForm]
	}
	idx = strings.Index(lowerForm, "action=")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(form[idx+len("action="):])
	if rest == "" {
		return ""
	}
	quote := rest[0]
	if quote != '\'' && quote != '"' {
		end := strings.IndexAny(rest, " \t\r\n>")
		if end < 0 {
			return rest
		}
		return rest[:end]
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, quote)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
