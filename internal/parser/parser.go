package parser

import (
	"encoding/json"
	"strings"
)

type NucleiFinding struct {
	TemplateID       string     `json:"template-id"`
	Name             string     `json:"name"`
	Severity         string     `json:"severity"`
	MatchedAt        string     `json:"matched-at"`
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
	allowed := make(map[string]struct{}, len(allowedSeverities))
	for _, severity := range allowedSeverities {
		normalized := strings.ToLower(strings.TrimSpace(severity))
		if normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}

	lines := strings.Split(rawOutput, "\n")
	findings := make([]NucleiFinding, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var finding NucleiFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			return nil, err
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

	return findings, nil
}
