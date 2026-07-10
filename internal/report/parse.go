package report

import (
	"regexp"
	"strings"
)

var headingRe = regexp.MustCompile(`^\[=\]\s+(.+)$`)
var findingRe = regexp.MustCompile(`^\[!\]\s+(.+)$`)
var actionRe = regexp.MustCompile(`^\[\*\]\s+(.+)$`)
var dividerRe = regexp.MustCompile(`^[=\-+]{3,}$`)
var bulletRe = regexp.MustCompile(`^\s*-\s+(.+)$`)
var kvRe = regexp.MustCompile(`^(-?\s*[\w\s]+?)\s*:\s*(.+)$`)

type Section struct {
	Kind    string
	Title   string
	Content string
	Items   []Item
}

type Item struct {
	Key      string
	Value    string
	IsBullet bool
	IsCode   bool
}

func Parse(raw string) (sections []Section) {
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
		if strings.HasPrefix(line, "|") && strings.HasSuffix(line, "|") {
			continue
		}

		if m := headingRe.FindStringSubmatch(line); m != nil {
			title := strings.TrimSpace(m[1])
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
			sections = append(sections, Section{
				Kind:    "heading",
				Title:   title,
				Content: strings.Join(contentLines, "\n"),
			})
			continue
		}

		if m := findingRe.FindStringSubmatch(line); m != nil {
			title := strings.TrimSpace(m[1])
			var items []Item
			var currentKey, currentVal string
			flush := func() {
				if currentKey != "" {
					items = append(items, Item{Key: currentKey, Value: currentVal})
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
					items = append(items, Item{Value: strings.TrimSpace(bm[1]), IsBullet: true})
					i++
					continue
				}
				if km := kvRe.FindStringSubmatch(next); km != nil {
					flush()
					currentKey = strings.TrimSpace(km[1])
					currentVal = strings.TrimSpace(km[2])
					i++
					continue
				}
				if next == "```" {
					i++
					codeLines := []string{}
					for i < len(lines) {
						cl := strings.TrimRight(lines[i], "\r")
						if strings.TrimSpace(cl) == "```" {
							i++
							break
						}
						codeLines = append(codeLines, cl)
						i++
					}
					flush()
					items = append(items, Item{IsCode: true, Value: strings.Join(codeLines, "\n")})
					continue
				}
				if currentKey != "" {
					currentVal += " " + next
				}
				i++
			}
			flush()
			sections = append(sections, Section{
				Kind:  "finding",
				Title: title,
				Items: items,
			})
			continue
		}

		if m := actionRe.FindStringSubmatch(line); m != nil {
			title := strings.TrimSpace(m[1])
			var items []Item
			var currentKey, currentVal string
			flush := func() {
				if currentKey != "" {
					items = append(items, Item{Key: currentKey, Value: currentVal})
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
					currentKey = strings.TrimSpace(km[1])
					currentVal = strings.TrimSpace(km[2])
					i++
					continue
				}
				if next == "```" {
					i++
					codeLines := []string{}
					for i < len(lines) {
						cl := strings.TrimRight(lines[i], "\r")
						if strings.TrimSpace(cl) == "```" {
							i++
							break
						}
						codeLines = append(codeLines, cl)
						i++
					}
					flush()
					items = append(items, Item{IsCode: true, Value: strings.Join(codeLines, "\n")})
					continue
				}
				if currentKey != "" {
					currentVal += " " + next
				}
				i++
			}
			flush()
			sections = append(sections, Section{
				Kind:  "action",
				Title: title,
				Items: items,
			})
			continue
		}

		if len(sections) > 0 {
			last := &sections[len(sections)-1]
			if last.Content == "" {
				last.Content = line
			} else {
				last.Content += "\n" + line
			}
		}
	}
	return
}
