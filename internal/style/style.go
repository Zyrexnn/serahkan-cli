package style

import (
	"fmt"
	"io"
	"strings"

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
	banner := `   _____ ______ _____          _    _  _    _          _ _ 
  / ____|  ____|  __ \   /\   | |  | || |  / \   /\   | | |
 | (___ | |__  | |__) | /  \  | |__| || | /  /  /  \  | | |
  \___ \|  __| |  _  / / /\ \ |  __  || |/  /  / /\ \ | | |
  ____) | |____| | \ \/ ____ \| |  | || |\  \ / ____ \| | |
 |_____/|______|_|  \_\_/    \_\_|  |_||_| \_/_/    \_\_|_|`

	dim := color.New(color.FgHiBlack)
	cyan := color.New(color.FgCyan, color.Bold)
	ver := color.New(color.FgGreen, color.Bold)

	fmt.Fprintln(w, cyan.Sprint(banner))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s\n", dim.Sprint("AI-powered Nuclei orchestration engine"), ver.Sprint("[v"+version+"]"))
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
	fmt.Fprintf(w, "  %-12s %s\n", Purple.Sprint("AI Stat :"), Bold(aiStatus))
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

func PrintAIReport(w io.Writer, report string) {
	sep := DimWhite.Sprint("═══════════════════════════════════════════════════════════════════════════════")
	title := Cyan.Sprint("                       AI DEFENSIVE ANALYSIS REPORT")
	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  %s\n", title)
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)

	lines := strings.Split(report, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			fmt.Fprintln(w)
		} else if strings.HasPrefix(trimmed, "[=]") {
			header := strings.TrimPrefix(trimmed, "[=]")
			fmt.Fprintf(w, "  %s %s\n", Green.Sprint("[=]"), Green.Sprint(strings.TrimSpace(header)))
		} else if strings.HasPrefix(trimmed, "[!]") {
			inner := strings.TrimPrefix(trimmed, "[!]")
			fmt.Fprintf(w, "  %s %s\n", Red.Sprint("[!]"), Red.Sprint(strings.TrimSpace(inner)))
		} else if strings.HasPrefix(trimmed, "[*]") {
			inner := strings.TrimPrefix(trimmed, "[*]")
			fmt.Fprintf(w, "  %s %s\n", Cyan.Sprint("[*]"), Cyan.Sprint(strings.TrimSpace(inner)))
		} else if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "===") || strings.HasPrefix(trimmed, "+-") {
			fmt.Fprintf(w, "  %s\n", DimWhite.Sprint(trimmed))
		} else if strings.HasPrefix(trimmed, "$ ") {
			cmd := strings.TrimPrefix(trimmed, "$ ")
			fmt.Fprintf(w, "    $ %s\n", Yellow.Sprint(cmd))
		} else if strings.HasPrefix(trimmed, "- Target Host") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), Target(strings.TrimSpace(parts[1])))
			} else {
				fmt.Fprintf(w, "  %s\n", line)
			}
		} else if strings.HasPrefix(trimmed, "- Risk Status") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), Red.Sprint(strings.TrimSpace(parts[1])))
			} else {
				fmt.Fprintf(w, "  %s\n", line)
			}
		} else if strings.HasPrefix(trimmed, "- Risk Level") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				severity := strings.TrimSpace(parts[1])
				var colored string
				switch strings.ToLower(severity) {
				case "critical", "high":
					colored = Red.Sprint(severity)
				case "medium":
					colored = Yellow.Sprint(severity)
				default:
					colored = Dim(severity)
				}
				fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), colored)
			} else {
				fmt.Fprintf(w, "  %s\n", line)
			}
		} else if strings.HasPrefix(trimmed, "Targeted Component:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), Cyan.Sprint(strings.TrimSpace(parts[1])))
			} else {
				fmt.Fprintf(w, "  %s\n", line)
			}
		} else {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
}

func PrintAIReportHeader(w io.Writer) {
	sep := DimWhite.Sprint("═══════════════════════════════════════════════════════════════════════════════")
	title := Cyan.Sprint("                       AI DEFENSIVE ANALYSIS REPORT")
	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  %s\n", title)
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)
}

func PrintAIReportFooter(w io.Writer) {
	sep := DimWhite.Sprint("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
}

func PrintAIReportLine(w io.Writer, line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		fmt.Fprintln(w)
	} else if strings.HasPrefix(trimmed, "[=]") {
		header := strings.TrimPrefix(trimmed, "[=]")
		fmt.Fprintf(w, "  %s %s\n", Green.Sprint("[=]"), Green.Sprint(strings.TrimSpace(header)))
	} else if strings.HasPrefix(trimmed, "[!]") {
		inner := strings.TrimPrefix(trimmed, "[!]")
		fmt.Fprintf(w, "  %s %s\n", Red.Sprint("[!]"), Red.Sprint(strings.TrimSpace(inner)))
	} else if strings.HasPrefix(trimmed, "[*]") {
		inner := strings.TrimPrefix(trimmed, "[*]")
		fmt.Fprintf(w, "  %s %s\n", Cyan.Sprint("[*]"), Cyan.Sprint(strings.TrimSpace(inner)))
	} else if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "===") || strings.HasPrefix(trimmed, "+-") {
		fmt.Fprintf(w, "  %s\n", DimWhite.Sprint(trimmed))
	} else if strings.HasPrefix(trimmed, "$ ") {
		cmd := strings.TrimPrefix(trimmed, "$ ")
		fmt.Fprintf(w, "    $ %s\n", Yellow.Sprint(cmd))
	} else if strings.HasPrefix(trimmed, "- Target Host") {
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), Target(strings.TrimSpace(parts[1])))
		} else {
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else if strings.HasPrefix(trimmed, "- Risk Status") {
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), Red.Sprint(strings.TrimSpace(parts[1])))
		} else {
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else if strings.HasPrefix(trimmed, "- Risk Level") {
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			severity := strings.TrimSpace(parts[1])
			var colored string
			switch strings.ToLower(severity) {
			case "critical", "high":
				colored = Red.Sprint(severity)
			case "medium":
				colored = Yellow.Sprint(severity)
			default:
				colored = Dim(severity)
			}
			fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), colored)
		} else {
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else if strings.HasPrefix(trimmed, "Targeted Component:") {
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			fmt.Fprintf(w, "    %s : %s\n", DimWhite.Sprint(parts[0]), Cyan.Sprint(strings.TrimSpace(parts[1])))
		} else {
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

func PrintVersionInfo(w io.Writer, version, commit, date, goVersion, osArch string) {
	sep := DimWhite.Sprint("─────────────────────────────────────────────────────")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  %-12s %s\n", Cyan.Sprint("serahkan"), Green.Sprint(version))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("commit :"), Dim(commit))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("built  :"), Dim(date))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("go     :"), Dim(goVersion))
	fmt.Fprintf(w, "  %-12s %s\n", DimWhite.Sprint("os/arch:"), Dim(osArch))
	fmt.Fprintln(w, sep)
}

func PrintDoctorHeader(w io.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", Cyan.Sprint("serahkan doctor"))
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
