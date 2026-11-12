package main

import (
	"strings"

	"github.com/repentandliveholy/netriser/internal/term"
)

// colorLogLine colors a log line by its level: warnings yellow, errors red,
// recovery actions cyan.
func colorLogLine(s term.Style, line string) string {
	switch {
	case strings.Contains(line, "] [ERROR]"):
		return s.Red(line)
	case strings.Contains(line, "] [WARN]"):
		return s.Yellow(line)
	case strings.Contains(line, "] [RECOVERY]"):
		return s.Cyan(line)
	case strings.Contains(line, "RESTORED"), strings.Contains(line, "successfully restored"):
		return s.Green(line)
	}
	return line
}

// colorStatus highlights the health verdict, probe results and headings of
// the status report.
func colorStatus(s term.Style, report string) string {
	if !s.On {
		return report
	}
	lines := strings.Split(report, "\n")
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "Overall Health:") && strings.Contains(l, "UNHEALTHY"):
			lines[i] = s.Red(l)
		case strings.HasPrefix(l, "Overall Health:"):
			lines[i] = s.Green(l)
		case strings.HasPrefix(l, "  [OK]"):
			lines[i] = s.Green("  [OK]") + l[len("  [OK]"):]
		case strings.HasPrefix(l, "  [FAIL]"):
			lines[i] = s.Red("  [FAIL]") + l[len("  [FAIL]"):]
		case strings.HasPrefix(l, "Consecutive Failures:") && !strings.HasSuffix(l, " 0"):
			lines[i] = s.Yellow(l)
		case strings.HasPrefix(l, "Quarantined Services:") && !strings.Contains(l, "[None]"):
			lines[i] = s.Yellow(l)
		case strings.HasPrefix(l, "Observation Mode:") && strings.HasSuffix(l, "true"):
			lines[i] = s.Yellow(l)
		case strings.HasPrefix(l, "=====") || strings.Contains(l, "STATUS REPORT") || strings.HasPrefix(l, "---"):
			lines[i] = s.Title(l)
		}
	}
	return strings.Join(lines, "\n")
}
