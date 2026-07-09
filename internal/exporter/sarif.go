package exporter

import (
	"encoding/json"
	"fmt"

	"github.com/Zyrexnn/serahkan-cli/internal/parser"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool       `json:"tool"`
	Results   []sarifResult   `json:"results"`
	Artifacts []sarifArtifact `json:"artifacts,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     sarifMessage           `json:"shortDescription,omitempty"`
	FullDescription      sarifMessage           `json:"fullDescription,omitempty"`
	DefaultConfiguration sarifRuleConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level,omitempty"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
}

func severityToSarifLevel(severity string) string {
	switch severity {
	case "critical", "high", "medium":
		return "error"
	case "low":
		return "warning"
	default:
		return "note"
	}
}

func ExportSarif(findings []parser.NucleiFinding, target, cliVersion string) (string, error) {
	seenRules := make(map[string]*sarifRule)
	ruleOrder := make([]string, 0)
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := f.TemplateID
		if ruleID == "" {
			ruleID = f.Name
		}
		if ruleID == "" {
			continue
		}

		if _, exists := seenRules[ruleID]; !exists {
			level := severityToSarifLevel(f.Severity)
			desc := f.Info.Description
			rule := &sarifRule{
				ID:   ruleID,
				Name: f.Name,
				ShortDescription: sarifMessage{
					Text: f.Name,
				},
				DefaultConfiguration: sarifRuleConfiguration{
					Level: level,
				},
				Properties: map[string]interface{}{
					"tags": f.Info.Tags,
				},
			}
			if desc != "" {
				rule.FullDescription = sarifMessage{Text: desc}
			}
			seenRules[ruleID] = rule
			ruleOrder = append(ruleOrder, ruleID)
		}

		level := severityToSarifLevel(f.Severity)
		message := f.Name
		if f.Info.Description != "" {
			message = f.Info.Description
		}

		result := sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: message},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.MatchedAt,
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"severity":     f.Severity,
				"template-id":  f.TemplateID,
				"host":         f.Host,
				"curl-command": f.CurlCommand,
			},
		}
		results = append(results, result)
	}

	rules := make([]sarifRule, 0, len(ruleOrder))
	for _, id := range ruleOrder {
		rules = append(rules, *seenRules[id])
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "serahkan-cli",
						Version:        cliVersion,
						InformationURI: "https://github.com/Zyrexnn/serahkan-cli",
						Rules:          rules,
					},
				},
				Results:   results,
				Artifacts: nil,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	filename := GenerateFilename(target, "sarif.json")
	return SaveToFile(filename, data)
}
