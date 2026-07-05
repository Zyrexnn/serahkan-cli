package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type NucleiFinding struct {
	TemplateID       string     `json:"template-id"`
	Name             string     `json:"name"`
	Severity         string     `json:"severity"`
	Host             string     `json:"host"`
	MatchedAt        string     `json:"matched-at"`
	CurlCommand      string     `json:"curl-command"`
	Request          string     `json:"request"`
	Response         string     `json:"response"`
	ExtractedResults []string   `json:"extracted-results"`
	Info             NucleiInfo `json:"info"`
}

type NucleiInfo struct {
	Name        string                 `json:"name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description,omitempty"`
	Reference   []string               `json:"reference,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type Options struct {
	Verbose   bool
	LogWriter io.Writer
}

var wafBlockPatterns = []string{
	"Error 1015",
	"You are being rate limited",
	"Access denied | freemodel.dev used Cloudflare to restrict access",
	"Access denied",
	"Request blocked",
	"Security block",
	"WAF Notification",
	"403 Forbidden",
	"Attention Required! | Cloudflare",
	"Please enable cookies",
	"Checking your browser",
	"Verify you are human",
}

type ParseResult struct {
	Findings           []NucleiFinding
	TotalLines         int
	MalformedLines     int
	RawFindings        int
	FilteredBySeverity int
	WAFBlocked         int
}

type DeduplicatedFinding struct {
	Representative NucleiFinding
	AffectedURLs   []string
	Count          int
}

func ParseAndFilter(rawOutput string, allowedSeverities []string) ([]NucleiFinding, error) {
	result, err := ParseAndFilterDetailed(strings.NewReader(rawOutput), allowedSeverities, Options{})
	if err != nil {
		return nil, err
	}

	return result.Findings, nil
}

func ParseAndFilterReader(input io.Reader, allowedSeverities []string, options Options) ([]NucleiFinding, error) {
	result, err := ParseAndFilterDetailed(input, allowedSeverities, options)
	if err != nil {
		return nil, err
	}

	return result.Findings, nil
}

func ParseAndFilterDetailed(input io.Reader, allowedSeverities []string, options Options) (ParseResult, error) {
	if options.LogWriter == nil {
		options.LogWriter = io.Discard
	}

	allowed := make(map[string]struct{}, len(allowedSeverities))
	for _, severity := range allowedSeverities {
		normalized := strings.ToLower(strings.TrimSpace(severity))
		if normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}

	result := ParseResult{
		Findings: make([]NucleiFinding, 0),
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		result.TotalLines++

		var finding NucleiFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			result.MalformedLines++
			if options.Verbose {
				fmt.Fprintf(options.LogWriter, "[WARN] Skipping malformed Nuclei JSONL line: %v\n", err)
			}
			continue
		}

		if finding.Name == "" {
			finding.Name = finding.Info.Name
		}

		if finding.Severity == "" {
			finding.Severity = finding.Info.Severity
		}

		result.RawFindings++

		severityKey := strings.ToLower(strings.TrimSpace(finding.Severity))
		if _, ok := allowed[severityKey]; !ok {
			result.FilteredBySeverity++
			if options.Verbose {
				fmt.Fprintf(options.LogWriter, "[DEBUG] Skipping finding %q (severity=%q, not in allowed list)\n", finding.Name, finding.Severity)
			}
			continue
		}

		if options.Verbose {
			fmt.Fprintf(options.LogWriter, "[DEBUG] Matched finding: %q (severity=%q, matched-at=%q)\n", finding.Name, finding.Severity, finding.MatchedAt)
		}

		if isWAFBlocked(finding) {
			result.WAFBlocked++
			if options.Verbose {
				fmt.Fprintf(options.LogWriter, "[WARN] Skipping WAF-blocked finding %q (response contains security block pattern)\n", finding.Name)
			}
			continue
		}

		result.Findings = append(result.Findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return ParseResult{}, err
	}

	return result, nil
}

func isWAFBlocked(finding NucleiFinding) bool {
	body := strings.ToLower(finding.Response)
	if body == "" {
		return false
	}
	for _, pattern := range wafBlockPatterns {
		if strings.Contains(body, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func DeduplicateFindings(findings []NucleiFinding) []DeduplicatedFinding {
	type groupKey struct {
		templateID string
		name       string
		severity   string
	}

	groups := make(map[groupKey]*DeduplicatedFinding)
	order := make([]groupKey, 0)

	for _, f := range findings {
		key := groupKey{
			templateID: strings.TrimSpace(f.TemplateID),
			name:       strings.TrimSpace(f.Name),
			severity:   strings.ToLower(strings.TrimSpace(f.Severity)),
		}

		if key.templateID == "" && key.name == "" {
			key.name = f.MatchedAt
		}

		if existing, ok := groups[key]; ok {
			existing.AffectedURLs = append(existing.AffectedURLs, f.MatchedAt)
			existing.Count++
		} else {
			groups[key] = &DeduplicatedFinding{
				Representative: f,
				AffectedURLs:   []string{f.MatchedAt},
				Count:          1,
			}
			order = append(order, key)
		}
	}

	result := make([]DeduplicatedFinding, 0, len(order))
	for _, key := range order {
		result = append(result, *groups[key])
	}

	return result
}
