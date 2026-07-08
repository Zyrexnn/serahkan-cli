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
	b.WriteString(`<div class="report-block">`)
	b.WriteString(fmt.Sprintf(`<div class="block-title">%s</div>`, s.title))
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg-primary: #09090b;
  --bg-secondary: #18181b;
  --bg-tertiary: #27272a;
  --border-color: #27272a;
  --text-primary: #fafafa;
  --text-secondary: #a1a1aa;
  --text-muted: #71717a;
  --accent-green: #22c55e;
  --accent-green-dim: rgba(34,197,94,0.15);
  --accent-red: #ef4444;
  --accent-red-dim: rgba(239,68,68,0.15);
  --accent-amber: #f59e0b;
  --accent-amber-dim: rgba(245,158,11,0.15);
  --accent-blue: #3b82f6;
  --accent-blue-dim: rgba(59,130,246,0.15);
  --accent-purple: #a855f7;
  --accent-purple-dim: rgba(168,85,247,0.15);
}

*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg-primary);color:var(--text-primary);font-family:'Inter',system-ui,-apple-system,sans-serif;line-height:1.7;min-height:100vh;-webkit-font-smoothing:antialiased}

.container{max-width:1000px;margin:0 auto;padding:48px 32px}

/* Header */
.header{text-align:center;padding:56px 32px 48px;margin-bottom:40px;border-bottom:1px solid var(--border-color);position:relative;overflow:hidden}
.header::before{content:'';position:absolute;top:0;left:50%%;transform:translateX(-50%%);width:400px;height:400px;background:radial-gradient(circle,rgba(34,197,94,0.08) 0%%,transparent 70%%);pointer-events:none}
.header .logo{font-size:3em;font-weight:800;letter-spacing:16px;margin-bottom:12px;position:relative;display:inline-block;background:linear-gradient(135deg,var(--accent-green) 0%%,#4ade80 50%%,var(--accent-green) 100%%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header .tagline{color:var(--text-muted);font-size:0.82em;letter-spacing:4px;text-transform:uppercase;font-weight:500}
.header .version{display:inline-block;margin-top:12px;padding:4px 12px;background:var(--accent-green-dim);color:var(--accent-green);border-radius:20px;font-size:0.72em;font-weight:600;letter-spacing:1px;text-transform:uppercase}

/* Meta Grid */
.meta-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:40px}
.meta-card{background:var(--bg-secondary);border:1px solid var(--border-color);padding:20px 18px;border-radius:12px;transition:all 0.2s ease}
.meta-card:hover{border-color:#3f3f46;transform:translateY(-1px)}
.meta-card .label{color:var(--text-muted);font-size:0.7em;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;font-weight:600}
.meta-card .value{color:var(--text-primary);font-size:1em;font-weight:600;word-break:break-all}
.meta-card.highlight{border-color:var(--accent-green);background:linear-gradient(135deg,var(--accent-green-dim) 0%%,var(--bg-secondary) 100%%)}
.meta-card.highlight .label{color:var(--accent-green)}

/* Report Block */
.report-block{margin-bottom:24px;padding:28px;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px}
.block-title{color:var(--text-primary);font-size:0.85em;font-weight:700;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border-color);text-transform:uppercase;letter-spacing:2px;display:flex;align-items:center;gap:10px}
.block-title::before{content:'';width:4px;height:18px;background:var(--accent-green);border-radius:2px}
.block-content{color:var(--text-secondary);font-size:0.9em;line-height:1.9;white-space:pre-wrap}

/* Finding Card */
.finding-card{margin-bottom:20px;padding:24px;background:var(--bg-secondary);border:1px solid var(--border-color);border-left:3px solid var(--accent-red);border-radius:12px;position:relative}
.finding-header{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.finding-icon{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;background:var(--accent-red-dim);color:var(--accent-red);font-weight:800;font-size:0.85em;border-radius:8px;flex-shrink:0}
.finding-title{color:var(--text-primary);font-size:1em;font-weight:600}
.finding-urls{margin-bottom:18px;padding:16px 18px;background:var(--bg-primary);border-radius:8px;border:1px solid var(--border-color)}
.finding-url-label{color:var(--accent-green);font-size:0.7em;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px;font-weight:600}
.finding-url{color:var(--accent-blue);font-size:0.85em;font-family:'JetBrains Mono',monospace;padding:4px 0;word-break:break-all;line-height:1.6}
.finding-detail{margin-bottom:10px;font-size:0.88em;display:flex;gap:8px}
.detail-key{color:var(--text-muted);font-weight:600;min-width:100px}
.detail-value{color:var(--text-secondary);flex:1}
.finding-code{margin-top:14px}
.finding-code pre{background:var(--bg-primary);border:1px solid var(--border-color);border-radius:8px;padding:16px 18px;font-family:'JetBrains Mono',monospace;font-size:0.82em;color:var(--text-secondary);line-height:1.7;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word}

/* Action Card */
.action-card{margin-bottom:20px;padding:24px;background:var(--bg-secondary);border:1px solid var(--border-color);border-left:3px solid var(--accent-green);border-radius:12px;position:relative}
.action-header{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.action-icon{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;background:var(--accent-green-dim);color:var(--accent-green);font-weight:800;font-size:0.85em;border-radius:8px;flex-shrink:0}
.action-title{color:var(--text-primary);font-size:1em;font-weight:600}
.action-detail{margin-bottom:10px;font-size:0.88em;display:flex;gap:8px}
.action-code{margin-top:14px}
.action-code pre{background:var(--bg-primary);border:1px solid var(--border-color);border-radius:8px;padding:16px 18px;font-family:'JetBrains Mono',monospace;font-size:0.82em;color:var(--text-secondary);line-height:1.7;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word}

/* Footer */
.footer{text-align:center;padding:40px 0;margin-top:48px;border-top:1px solid var(--border-color)}
.footer p{color:var(--text-muted);font-size:0.78em;margin-bottom:6px;letter-spacing:0.5px}
.footer .brand{color:var(--text-muted);font-weight:600}
.footer .brand span{color:var(--accent-green)}

/* Summary Stats */
.summary-section{margin-bottom:40px;padding:32px;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:12px}
.summary-title{color:var(--text-primary);font-size:0.85em;font-weight:700;margin-bottom:20px;text-transform:uppercase;letter-spacing:2px;display:flex;align-items:center;gap:10px}
.summary-title::before{content:'';width:4px;height:18px;background:var(--accent-blue);border-radius:2px}
.summary-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
.summary-item{text-align:center;padding:20px;background:var(--bg-primary);border-radius:10px;border:1px solid var(--border-color)}
.summary-item .number{font-size:2em;font-weight:800;margin-bottom:6px}
.summary-item .number.green{color:var(--accent-green)}
.summary-item .number.red{color:var(--accent-red)}
.summary-item .number.amber{color:var(--accent-amber)}
.summary-item .label{color:var(--text-muted);font-size:0.75em;text-transform:uppercase;letter-spacing:1px;font-weight:600}

/* Responsive */
@media(max-width:768px){
  .container{padding:24px 16px}
  .header .logo{font-size:2em;letter-spacing:8px}
  .meta-grid{grid-template-columns:repeat(2,1fr)}
  .summary-grid{grid-template-columns:1fr}
  .finding-detail,.action-detail{flex-direction:column;gap:4px}
  .detail-key{min-width:auto}
}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="logo">SERAHKAN</div>
<div class="tagline">AI-Powered Security Analysis Report</div>
<div class="version">CLI %s</div>
</div>
<div class="meta-grid">
<div class="meta-card highlight">
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
<div class="label">Scan Duration</div>
<div class="value">%s</div>
</div>
</div>
%s
<div class="footer">
<p class="brand"><span>SERAHKAN</span> CLI Security Report</p>
<p>&mdash; %s &mdash;</p>
</div>
</div>
</body>
</html>`,
		versionLabel(data.Version),
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

func versionLabel(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}
