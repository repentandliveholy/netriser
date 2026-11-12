// Package term decides whether output may use ANSI colors and provides the
// styles used by setup, status and log output.
package term

import (
	"io"
	"os"
)

// Style applies ANSI styles when enabled; the zero value prints plain text.
type Style struct{ On bool }

// For returns a Style enabled when w is a terminal, NO_COLOR is unset and TERM
// is not "dumb". On Windows it also switches the console to ANSI processing.
func For(w io.Writer) Style {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return Style{}
	}
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return Style{}
	}
	return Style{On: enableANSI(f)}
}

func (s Style) wrap(code, text string) string {
	if !s.On || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) Bold(t string) string   { return s.wrap("1", t) }
func (s Style) Dim(t string) string    { return s.wrap("2", t) }
func (s Style) Red(t string) string    { return s.wrap("31", t) }
func (s Style) Green(t string) string  { return s.wrap("32", t) }
func (s Style) Yellow(t string) string { return s.wrap("33", t) }
func (s Style) Cyan(t string) string   { return s.wrap("36", t) }
func (s Style) Title(t string) string  { return s.wrap("1;36", t) }

// Reverse highlights the selected menu option with a background.
func (s Style) Reverse(t string) string { return s.wrap("7", t) }
