package style

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	reportpkg "github.com/Zyrexnn/serahkan-cli/internal/report"
	"github.com/fatih/color"
)

var (
	Cyan     = color.New(color.FgCyan, color.Bold)
	Green    = color.New(color.FgGreen, color.Bold)
	Purple   = color.New(color.FgMagenta, color.Bold)
	Grey     = color.New(color.FgHiBlack)
	Red      = color.New(color.FgRed, color.Bold)
	Yellow   = color.New(color.FgYellow, color.Bold)
	White    = color.New(color.FgWhite, color.Bold)
	DimWhite = color.New(color.FgHiBlack)
)

var (
	TagScan    = color.New(color.FgCyan, color.Bold).Sprint("[SCAN]")
	TagFilter  = color.New(color.FgMagenta, color.Bold).Sprint("[FILTER]")
	TagAI      = color.New(color.FgGreen, color.Bold).Sprint("[AI]")
	TagWarn    = color.New(color.FgYellow, color.Bold).Sprint("[WARN]")
	TagInfo    = color.New(color.FgHiBlack).Sprint("[INFO]")
	TagDebug   = color.New(color.FgHiBlack).Sprint("[DEBUG]")
	TagOK      = color.New(color.FgGreen, color.Bold).Sprint("[OK]")
	TagFail    = color.New(color.FgRed, color.Bold).Sprint("[FAIL]")
	TagSkip    = color.New(color.FgYellow).Sprint("[SKIP]")
	TagBlocked = color.New(color.FgRed, color.Bold).Sprint("[BLOCKED]")
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func ansiVisibleLen(s string) int {
	return len([]rune(ansiRe.ReplaceAllString(s, "")))
}

func termWidth() int {
	if s := strings.TrimSpace(os.Getenv("COLUMNS")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 40 {
			return n
		}
	}
	return 80
}

func wrapText(s string, width int) []string {
	if width <= 0 {
		width = 80
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		var split []string
		for _, w := range words {
			if ansiVisibleLen(w) > width {
				runes := []rune(w)
				for i := 0; i < len(runes); i += width {
					end := i + width
					if end > len(runes) {
						end = len(runes)
					}
					split = append(split, string(runes[i:end]))
				}
			} else {
				split = append(split, w)
			}
		}
		line := split[0]
		lineLen := ansiVisibleLen(line)
		for _, w := range split[1:] {
			wLen := ansiVisibleLen(w)
			if lineLen+1+wLen <= width {
				line += " " + w
				lineLen += 1 + wLen
			} else {
				out = append(out, line)
				line = w
				lineLen = wLen
			}
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func Target(value string) string {
	return Cyan.Sprint(value)
}

func Success(value string) string {
	return Green.Sprint(value)
}

func Metric(value string) string {
	return Purple.Sprint(value)
}

func Dim(value string) string {
	return Grey.Sprint(value)
}

func Warn(value string) string {
	return Yellow.Sprint(value)
}

func Danger(value string) string {
	return Red.Sprint(value)
}

func Bold(value string) string {
	return White.Sprint(value)
}

func Label(label, value string) string {
	return fmt.Sprintf("%s %s", DimWhite.Sprint(label), value)
}

func PrintBanner(w io.Writer, version string) {
	dim := color.New(color.FgHiBlack)
	cyan := color.New(color.FgCyan, color.Bold)
	ver := color.New(color.FgGreen, color.Bold)

	banner := `   _____ ______ _____          _    _  _    _          _ _ 
  / ____|  ____|  __ \   /\   | |  | || |  / \   /\   | | |
 | (___ | |__  | |__) | /  \  | |__| || | /  /  /  \  | | |
  \___ \|  __| |  _  / / /\ \ |  __  || |/  /  / /\ \ | | |
  ____) | |____| | \ \/ ____ \| |  | || |\  \ / ____ \| | |
 |_____/|______|_|  \_\_/    \_\_|  |_||_| \_/_/    \_\_|_|`

	fmt.Fprintln(w, cyan.Sprint(banner))
	fmt.Fprintf(w, "  %s %s\n", dim.Sprint("SERAHKAN CLI"), ver.Sprint("[v"+version+"]"))
	fmt.Fprintf(w, "  %s\n", dim.Sprint("AI-powered web security scanner"))
	fmt.Fprintf(w, "  %s\n", dim.Sprint("──────────────────────────────────────────────────────"))
	fmt.Fprintln(w)
}

func PrintScanHeader(w io.Writer, target, profile string) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-12s %s\n", Cyan.Sprint("Target :"), Target(target))
	fmt.Fprintf(w, "  %-12s %s\n", Purple.Sprint("Profile:"), Bold(profile))
	fmt.Fprintln(w)
}

func PrintScanSummary(w io.Writer, target string, findingCount int, aiUsed bool, aiStatus string, duration string) {
	fmt.Fprintln(w)
	sep := DimWhite.Sprint("─────────────────────────────────────────────────────")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  %-12s %s\n", Cyan.Sprint("Target  :"), Target(target))
	fmt.Fprintf(w, "  %-12s %s\n", Green.Sprint("Findings:"), Bold(fmt.Sprintf("%d", findingCount)))
	fmt.Fprintf(w, "  %-12s %s\n", Purple.Sprint("AI Used :"), Bold(fmt.Sprintf("%t", aiUsed)))
	fmt.Fprintf(w, "  %-12s %s\n", Purple.Sprint("AI      :"), Bold(aiStatus))
	fmt.Fprintf(w, "  %-12s %s\n", Grey.Sprint("Duration:"), Dim(duration))
	fmt.Fprintln(w, sep)
}

func PrintNoFindingsSummary(w io.Writer, target string, raw, filtered int, duration string) {
	fmt.Fprintln(w)
	sep := DimWhite.Sprint("─────────────────────────────────────────────────────")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  %-12s %s\n", Cyan.Sprint("Target  :"), Target(target))
	fmt.Fprintf(w, "  %-12s %s\n", Green.Sprint("Findings:"), Bold("0"))
	fmt.Fprintf(w, "  %-12s %s\n", Purple.Sprint("Raw     :"), Bold(fmt.Sprintf("%d", raw)))
	fmt.Fprintf(w, "  %-12s %s\n", Purple.Sprint("Filtered:"), Bold(fmt.Sprintf("%d", filtered)))
	fmt.Fprintf(w, "  %-12s %s\n", Grey.Sprint("Duration:"), Dim(duration))
	fmt.Fprintln(w, sep)
}

func printBoxedHeader(w io.Writer, title string) {
	width := termWidth() - 2
	if width < ansiVisibleLen(title)+4 {
		width = ansiVisibleLen(title) + 4
	}
	bc := strings.Repeat("=", width)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  %s%s%s\n", DimWhite.Sprint("+"), DimWhite.Sprint(bc), DimWhite.Sprint("+"))
	titleVis := ansiVisibleLen(title)
	pad := width - titleVis
	left := pad / 2
	right := pad - left
	fmt.Fprintf(w, "  %s%s%s%s%s\n", DimWhite.Sprint("|"), strings.Repeat(" ", left), title, strings.Repeat(" ", right), DimWhite.Sprint("|"))
	fmt.Fprintf(w, "  %s%s%s\n", DimWhite.Sprint("+"), DimWhite.Sprint(bc), DimWhite.Sprint("+"))
}

func printBoxedFooter(w io.Writer) {
	width := termWidth() - 2
	bc := strings.Repeat("=", width)
	fmt.Fprintf(w, "  %s%s%s\n", DimWhite.Sprint("+"), DimWhite.Sprint(bc), DimWhite.Sprint("+"))
	fmt.Fprintf(w, "\n")
}

func PrintAIReport(w io.Writer, report string) {
	sections := reportpkg.Parse(report)

	printBoxedHeader(w, Cyan.Sprint("SERAHKAN CLI - AI Defensive Analysis"))
	fmt.Fprintln(w)

	if len(sections) == 0 {
		for _, line := range strings.Split(strings.TrimSpace(report), "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
		printBoxedFooter(w)
		return
	}

	contentWidth := termWidth() - 8
	if contentWidth < 40 {
		contentWidth = 40
	}

	for _, section := range sections {
		switch section.Kind {
		case "heading":
			fmt.Fprintf(w, "  %s %s\n", Green.Sprint("[=]"), Green.Sprint(section.Title))
			if section.Content != "" {
				for _, line := range wrapText(section.Content, contentWidth) {
					fmt.Fprintf(w, "      %s\n", line)
				}
			}
		case "finding":
			fmt.Fprintf(w, "  %s %s\n", Red.Sprint("[!]"), Red.Sprint(section.Title))
			printReportItems(w, section.Items, contentWidth)
		case "action":
			fmt.Fprintf(w, "  %s %s\n", Cyan.Sprint("[*]"), Cyan.Sprint(section.Title))
			printReportItems(w, section.Items, contentWidth)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
	printBoxedFooter(w)
}

func printReportItems(w io.Writer, items []reportpkg.Item, contentWidth int) {
	for _, item := range items {
		switch {
		case item.IsCode:
			printReportCodeBlock(w, item.Value, contentWidth)
		case item.IsBullet:
			bulletIndent := "      - "
			bulletWrap := contentWidth - len(bulletIndent)
			if bulletWrap < 30 {
				bulletWrap = 30
			}
			valLines := wrapText(item.Value, bulletWrap)
			if len(valLines) == 0 {
				fmt.Fprintln(w, bulletIndent)
				continue
			}
			fmt.Fprintf(w, "%s%s\n", bulletIndent, valLines[0])
			hang := strings.Repeat(" ", len(bulletIndent))
			for _, l := range valLines[1:] {
				fmt.Fprintf(w, "%s%s\n", hang, l)
			}
		case item.Key != "":
			value := item.Value
			if strings.EqualFold(strings.TrimSpace(item.Key), "Risk Level") {
				value = colorSeverity(item.Value)
			}
			if strings.EqualFold(strings.TrimSpace(item.Key), "Target Host") {
				value = Target(item.Value)
			}
			keyStr := item.Key + ":"
			keyVis := len([]rune(item.Key)) + 1
			padNeeded := 24 - keyVis
			if padNeeded < 1 {
				padNeeded = 1
			}
			keyLabel := DimWhite.Sprint(keyStr) + strings.Repeat(" ", padNeeded)
			valWrap := contentWidth - keyVis - 2
			if valWrap < 30 {
				valWrap = 30
			}
			valLines := wrapText(value, valWrap)
			if len(valLines) == 0 {
				fmt.Fprintf(w, "      %s\n", keyLabel)
				continue
			}
			fmt.Fprintf(w, "      %s %s\n", keyLabel, valLines[0])
			hangIndent := strings.Repeat(" ", 6+keyVis+1)
			for _, l := range valLines[1:] {
				fmt.Fprintf(w, "%s%s\n", hangIndent, l)
			}
		}
	}
}

func colorSeverity(value string) string {
	severity := strings.TrimSpace(value)
	switch strings.ToLower(severity) {
	case "critical", "high":
		return Red.Sprint(severity)
	case "medium":
		return Yellow.Sprint(severity)
	case "low":
		return Cyan.Sprint(severity)
	default:
		return Dim(severity + " [informational]")
	}
}

func printReportCodeBlock(w io.Writer, code string, contentWidth int) {
	border := strings.Repeat("-", contentWidth)
	fmt.Fprintf(w, "      %s\n", DimWhite.Sprint(border))
	for _, line := range strings.Split(strings.TrimSpace(code), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(trimmed), "$ ") {
			fmt.Fprintf(w, "      %s\n", Yellow.Sprint(trimmed))
			continue
		}
		fmt.Fprintf(w, "      %s\n", trimmed)
	}
	fmt.Fprintf(w, "      %s\n", DimWhite.Sprint(border))
}

func PrintVersionInfo(w io.Writer, version, commit, date, goVersion, osArch string) {
	sep := DimWhite.Sprint("─────────────────────────────────────────────────────")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  %-12s %s\n", Cyan.Sprint("SERAHKAN CLI"), Green.Sprint(version))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("commit :"), Dim(commit))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("built  :"), Dim(date))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("go     :"), Dim(goVersion))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("os/arch:"), Dim(osArch))
	fmt.Fprintln(w, sep)
}

func PrintDoctorHeader(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", Cyan.Sprint("SERAHKAN CLI doctor"))
	fmt.Fprintf(w, "  %s\n", DimWhite.Sprint("─────────────────────────────────────────────────────"))
	fmt.Fprintln(w)
}

func PrintDoctorResult(w io.Writer, status, name, details string, debugLines []string, verbose bool) {
	var tag string
	switch status {
	case "OK":
		tag = TagOK
	case "FAIL":
		tag = TagFail
	default:
		tag = TagSkip
	}
	fmt.Fprintf(w, "  %-8s %-14s %s\n", tag, Bold(name), details)
	if verbose {
		for _, line := range debugLines {
			fmt.Fprintf(w, "           %-14s %s\n", "", Dim(line))
		}
	}
}

func PrintDoctorFooter(w io.Writer, hasFailure bool) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", DimWhite.Sprint("config precedence: flag > env > config file > default"))
	fmt.Fprintln(w)
}
