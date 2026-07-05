package exporter

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

var headingRe = regexp.MustCompile(`^\[=\]\s+(.+)$`)
var findingRe = regexp.MustCompile(`^\[!\]\s+(.+)$`)
var actionRe = regexp.MustCompile(`^\[\*\]\s+(.+)$`)
var dividerRe = regexp.MustCompile(`^[=\-+]{3,}$`)
var bulletRe = regexp.MustCompile(`^\s*-\s+(.+)$`)
var kvRe = regexp.MustCompile(`^(-?\s*[\w\s]+?)\s*:\s*(.+)$`)

func parseReportSections(raw string) (sections []reportSection) {
	lines := strings.Split(raw, "\n")
	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		i++

		if line == "" {
			continue
		}

		if dividerRe.MatchString(line) {
			continue
		}

		if strings.Contains(line, "AI DEFENSIVE ANALYSIS REPORT") {
			continue
		}
		if strings.Contains(line, "+-") && strings.Contains(line, "-+") {
			continue
		}

		if m := headingRe.FindStringSubmatch(line); m != nil {
			title := html.EscapeString(strings.TrimSpace(m[1]))
			var contentLines []string
			for i < len(lines) {
				next := strings.TrimSpace(lines[i])
				if headingRe.MatchString(next) || findingRe.MatchString(next) || actionRe.MatchString(next) {
					break
				}
				if dividerRe.MatchString(next) {
					i++
					continue
				}
				if next == "" {
					i++
					continue
				}
				contentLines = append(contentLines, next)
				i++
			}
			sections = append(sections, reportSection{
				kind:    "heading",
				title:   title,
				content: strings.Join(contentLines, "\n"),
			})
			continue
		}

		if m := findingRe.FindStringSubmatch(line); m != nil {
			title := html.EscapeString(strings.TrimSpace(m[1]))
			var items []reportItem
			var currentKey, currentVal string
			flush := func() {
				if currentKey != "" {
					items = append(items, reportItem{Key: currentKey, Value: currentVal})
					currentKey = ""
					currentVal = ""
				}
			}
			for i < len(lines) {
				next := strings.TrimSpace(lines[i])
				if findingRe.MatchString(next) || actionRe.MatchString(next) || headingRe.MatchString(next) {
					break
				}
				if dividerRe.MatchString(next) {
					i++
					continue
				}
				if next == "" {
					flush()
					i++
					continue
				}
				if bm := bulletRe.FindStringSubmatch(next); bm != nil {
					flush()
					items = append(items, reportItem{Value: html.EscapeString(strings.TrimSpace(bm[1])), IsBullet: true})
					i++
					continue
				}
				if km := kvRe.FindStringSubmatch(next); km != nil {
					flush()
					currentKey = html.EscapeString(strings.TrimSpace(km[1]))
					currentVal = html.EscapeString(strings.TrimSpace(km[2]))
					i++
					continue
				}
				if currentKey != "" {
					currentVal += " " + html.EscapeString(next)
				}
				i++
			}
			flush()
			sections = append(sections, reportSection{
				kind:  "finding",
				title: title,
				items: items,
			})
			continue
		}

		if m := actionRe.FindStringSubmatch(line); m != nil {
			title := html.EscapeString(strings.TrimSpace(m[1]))
			var items []reportItem
			var currentKey, currentVal string
			flush := func() {
				if currentKey != "" {
					items = append(items, reportItem{Key: currentKey, Value: currentVal})
					currentKey = ""
					currentVal = ""
				}
			}
			for i < len(lines) {
				next := strings.TrimSpace(lines[i])
				if findingRe.MatchString(next) || actionRe.MatchString(next) || headingRe.MatchString(next) {
					break
				}
				if dividerRe.MatchString(next) {
					i++
					continue
				}
				if next == "" {
					flush()
					i++
					continue
				}
				if km := kvRe.FindStringSubmatch(next); km != nil {
					flush()
					currentKey = html.EscapeString(strings.TrimSpace(km[1]))
					currentVal = html.EscapeString(strings.TrimSpace(km[2]))
					i++
					continue
				}
				if next == "```" {
					i++
					codeLines := []string{}
					for i < len(lines) {
						cl := strings.TrimSpace(lines[i])
						if cl == "```" {
							i++
							break
						}
						codeLines = append(codeLines, html.EscapeString(cl))
						i++
					}
					flush()
					items = append(items, reportItem{IsCode: true, Value: strings.Join(codeLines, "\n")})
					continue
				}
				if currentKey != "" {
					currentVal += " " + html.EscapeString(next)
				}
				i++
			}
			flush()
			sections = append(sections, reportSection{
				kind:  "action",
				title: title,
				items: items,
			})
			continue
		}

		if len(sections) > 0 {
			last := &sections[len(sections)-1]
			if last.content == "" {
				last.content = html.EscapeString(line)
			} else {
				last.content += "\n" + html.EscapeString(line)
			}
		}
	}
	return
}

type reportSection struct {
	kind    string
	title   string
	content string
	items   []reportItem
}

type reportItem struct {
	Key      string
	Value    string
	IsBullet bool
	IsCode   bool
}

func renderFindingHTML(s reportSection) string {
	var b strings.Builder
	b.WriteString(`<div class="finding-card">`)
	b.WriteString(fmt.Sprintf(`<div class="finding-header"><span class="finding-icon">!</span><span class="finding-title">%s</span></div>`, s.title))

	urls := []string{}
	for _, item := range s.items {
		if item.IsBullet {
			urls = append(urls, item.Value)
		}
	}
	if len(urls) > 0 {
		b.WriteString(`<div class="finding-urls"><div class="finding-url-label">Affected URLs</div>`)
		for _, u := range urls {
			b.WriteString(fmt.Sprintf(`<div class="finding-url">%s</div>`, u))
		}
		b.WriteString(`</div>`)
	}

	for _, item := range s.items {
		if item.IsBullet || item.Key == "" {
			continue
		}
		if item.IsCode {
			b.WriteString(fmt.Sprintf(`<div class="finding-code"><pre>%s</pre></div>`, item.Value))
			continue
		}
		b.WriteString(fmt.Sprintf(`<div class="finding-detail"><span class="detail-key">%s:</span> <span class="detail-value">%s</span></div>`, item.Key, item.Value))
	}

	b.WriteString(`</div>`)
	return b.String()
}

func renderActionHTML(s reportSection) string {
	var b strings.Builder
	b.WriteString(`<div class="action-card">`)
	b.WriteString(fmt.Sprintf(`<div class="action-header"><span class="action-icon">*</span><span class="action-title">%s</span></div>`, s.title))

	for _, item := range s.items {
		if item.Key == "" && item.IsCode {
			b.WriteString(fmt.Sprintf(`<div class="action-code"><pre>%s</pre></div>`, item.Value))
			continue
		}
		if item.Key != "" {
			b.WriteString(fmt.Sprintf(`<div class="action-detail"><span class="detail-key">%s:</span> <span class="detail-value">%s</span></div>`, item.Key, item.Value))
		}
	}

	b.WriteString(`</div>`)
	return b.String()
}

func renderHeadingHTML(s reportSection) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<div class="report-block"><div class="block-title">%s</div>`, s.title))
	if s.content != "" {
		b.WriteString(fmt.Sprintf(`<div class="block-content">%s</div>`, s.content))
	}
	b.WriteString(`</div>`)
	return b.String()
}

func ExportHTML(data ReportData) (string, error) {
	raw := StripANSI(data.AISummary)
	sections := parseReportSections(raw)

	timestamp := data.Timestamp.Format("2006-01-02 15:04:05 UTC")
	targetEsc := html.EscapeString(data.Target)

	var body strings.Builder
	for _, s := range sections {
		switch s.kind {
		case "finding":
			body.WriteString(renderFindingHTML(s))
		case "action":
			body.WriteString(renderActionHTML(s))
		case "heading":
			body.WriteString(renderHeadingHTML(s))
		}
	}

	htmlOut := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SERAHKAN Security Report - %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#d0d0d0;font-family:'Inter','Segoe UI',system-ui,sans-serif;line-height:1.6;min-height:100vh}
.container{max-width:960px;margin:0 auto;padding:40px 24px}

.header{text-align:center;padding:48px 24px 40px;margin-bottom:32px;border-bottom:2px solid #1a2e1a;background:linear-gradient(180deg,#0d120d 0%%,#0a0a0f 100%%)}
.header .logo{font-size:2.8em;font-weight:800;color:#00ff41;letter-spacing:12px;text-shadow:0 0 30px rgba(0,255,65,0.3);margin-bottom:8px}
.header .tagline{color:#555;font-size:0.85em;letter-spacing:3px;text-transform:uppercase}

.meta-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px}
.meta-card{background:#0d0f12;border:1px solid #1a1e24;padding:18px 16px;border-radius:6px}
.meta-card .label{color:#00ff41;font-size:0.7em;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px;font-weight:600}
.meta-card .value{color:#e0e0e0;font-size:1.05em;font-weight:500}

.report-block{margin-bottom:20px;padding:24px;background:#0d0f12;border:1px solid #1a1e24;border-radius:6px}
.block-title{color:#00ff41;font-size:1.1em;font-weight:700;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid #1a1e24;text-transform:uppercase;letter-spacing:1px}
.block-content{color:#b0b0b0;font-size:0.92em;line-height:1.8}

.finding-card{margin-bottom:16px;padding:20px;background:#0d0f12;border:1px solid #1a1e24;border-left:3px solid #ff4444;border-radius:6px}
.finding-header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.finding-icon{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:#ff4444;color:#fff;font-weight:800;font-size:0.85em;border-radius:4px;flex-shrink:0}
.finding-title{color:#e8e8e8;font-size:1.05em;font-weight:600}
.finding-urls{margin-bottom:14px;padding:12px 14px;background:#080a0c;border-radius:4px;border:1px solid #151820}
.finding-url-label{color:#00ff41;font-size:0.72em;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-weight:600}
.finding-url{color:#8888cc;font-size:0.85em;font-family:'Courier New',monospace;padding:3px 0;word-break:break-all}
.finding-detail{margin-bottom:8px;font-size:0.9em}
.detail-key{color:#777;font-weight:500}
.detail-value{color:#c8c8c8}
.finding-code{margin-top:10px}
.finding-code pre{background:#050709;border:1px solid #151820;border-radius:4px;padding:14px;font-family:'Courier New',monospace;font-size:0.85em;color:#aaa;line-height:1.6;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word}

.action-card{margin-bottom:16px;padding:20px;background:#0d0f12;border:1px solid #1a1e24;border-left:3px solid #00ff41;border-radius:6px}
.action-header{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.action-icon{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:#00ff41;color:#000;font-weight:800;font-size:0.85em;border-radius:4px;flex-shrink:0}
.action-title{color:#e8e8e8;font-size:1.05em;font-weight:600}
.action-detail{margin-bottom:8px;font-size:0.9em}
.action-code{margin-top:10px}
.action-code pre{background:#050709;border:1px solid #151820;border-radius:4px;padding:14px;font-family:'Courier New',monospace;font-size:0.85em;color:#aaa;line-height:1.6;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word}

.footer{text-align:center;padding:32px 0;margin-top:40px;border-top:1px solid #1a1e24;color:#444;font-size:0.78em}
.footer p{margin-bottom:4px}

@media(max-width:768px){
.header .logo{font-size:2em;letter-spacing:6px}
.meta-grid{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="logo">SERAHKAN</div>
<div class="tagline">AI-Powered Security Analysis Report</div>
</div>
<div class="meta-grid">
<div class="meta-card">
<div class="label">Target</div>
<div class="value">%s</div>
</div>
<div class="meta-card">
<div class="label">Findings</div>
<div class="value">%d</div>
</div>
<div class="meta-card">
<div class="label">AI Analysis</div>
<div class="value">%s</div>
</div>
<div class="meta-card">
<div class="label">Duration</div>
<div class="value">%s</div>
</div>
</div>
%s
<div class="footer">
<p>SERAHKAN CLI Security Report &mdash; %s</p>
<p>github.com/Zyrexnn/serahkan-cli</p>
</div>
</div>
</body>
</html>`,
		targetEsc,
		targetEsc,
		data.FindingCount,
		html.EscapeString(data.AIStatus),
		html.EscapeString(data.ScanDuration),
		body.String(),
		timestamp,
	)

	filename := GenerateFilename(data.Target, "html")
	savedPath, err := SaveToFile(filename, []byte(htmlOut))
	if err != nil {
		return "", err
	}

	return savedPath, nil
}
