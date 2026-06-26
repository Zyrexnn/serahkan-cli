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

func ParseAndFilter(rawOutput string, allowedSeverities []string) ([]NucleiFinding, error) {
	return ParseAndFilterReader(strings.NewReader(rawOutput), allowedSeverities)
}

func ParseAndFilterReader(input io.Reader, allowedSeverities []string) ([]NucleiFinding, error) {
	allowed := make(map[string]struct{}, len(allowedSeverities))
	for _, severity := range allowedSeverities {
		normalized := strings.ToLower(strings.TrimSpace(severity))
		if normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}

	findings := make([]NucleiFinding, 0)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var finding NucleiFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			fmt.Printf("[WARN] Skipping malformed Nuclei JSONL line: %v\n", err)
			continue
		}

		if finding.Name == "" {
			finding.Name = finding.Info.Name
		}

		if finding.Severity == "" {
			finding.Severity = finding.Info.Severity
		}

		if _, ok := allowed[strings.ToLower(strings.TrimSpace(finding.Severity))]; !ok {
			continue
		}

		findings = append(findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return findings, nil
}
