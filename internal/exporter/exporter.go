package exporter

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ReportData struct {
	Target       string
	Findings     string
	AISummary    string
	ScanDuration string
	Timestamp    time.Time
	FindingCount int
	AIUsed       bool
	AIStatus     string
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

var ansiToClass = map[string]string{
	"\x1b[1;36m": "ansi-cyan-bold",
	"\x1b[1;32m": "ansi-green-bold",
	"\x1b[1;35m": "ansi-purple-bold",
	"\x1b[37m":   "ansi-grey",
	"\x1b[1;31m": "ansi-red-bold",
	"\x1b[1;33m": "ansi-yellow-bold",
	"\x1b[1;37m": "ansi-white-bold",
	"\x1b[90m":   "ansi-dim-white",
	"\x1b[0m":    "",
}

func StripANSI(input string) string {
	return ansiRegex.ReplaceAllString(input, "")
}

func SanitizeForHTML(input string) string {
	input = strings.ReplaceAll(input, "&", "&amp;")
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#39;")
	return input
}

func ConvertANSIToHTML(input string) string {
	input = SanitizeForHTML(input)
	for code, class := range ansiToClass {
		escaped := strings.ReplaceAll(code, "\x1b", "\x1b")
		if class == "" {
			input = strings.ReplaceAll(input, escaped, "</span>")
		} else {
			input = strings.ReplaceAll(input, escaped, fmt.Sprintf(`<span class="%s">`, class))
		}
	}
	input = ansiRegex.ReplaceAllString(input, "")
	return input
}

func ExtractHost(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return "unknown"
	}
	host := u.Hostname()
	if host == "" {
		return "unknown"
	}
	return strings.ReplaceAll(host, ".", "_")
}

func GenerateFilename(target, ext string) string {
	host := ExtractHost(target)
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("report_%s_%s.%s", host, timestamp, ext)
}

func SaveToFile(filename string, content []byte) (string, error) {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	if err := os.WriteFile(absPath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return absPath, nil
}
