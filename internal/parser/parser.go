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

type ParseResult struct {
	Findings           []NucleiFinding
	TotalLines         int
	MalformedLines     int
	RawFindings        int
	FilteredBySeverity int
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

		result.Findings = append(result.Findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return ParseResult{}, err
	}

	return result, nil
}
