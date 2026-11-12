package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/repentandliveholy/netriser/internal/i18n"
	"github.com/repentandliveholy/netriser/internal/term"
)

// ErrCancelled is returned when the user declines to save or input ends.
var ErrCancelled = errors.New("setup cancelled; nothing was changed")

const wrapWidth = 78

type prompter struct {
	r    *bufio.Reader
	w    io.Writer
	lang string
	s    term.Style
	// existing marks defaults as the current settings rather than new values.
	existing bool
	// grouped is set after a heading or help text, so the next help text
	// continues the group instead of starting with a blank line.
	grouped bool
}

func (p *prompter) t(key string, args ...any) string { return i18n.T(p.lang, key, args...) }

func (p *prompter) printf(format string, args ...any) { fmt.Fprintf(p.w, format, args...) }

// explain prints dimmed, wrapped help text before a question.
func (p *prompter) explain(text string) {
	if !p.grouped {
		p.printf("\n")
	}
	p.grouped = true
	for _, l := range wrap(text, wrapWidth-2) {
		p.printf("  %s\n", p.s.Dim(l))
	}
}

// note prints wrapped plain text.
func (p *prompter) note(text string) {
	for _, l := range wrap(text, wrapWidth) {
		p.printf("%s\n", l)
	}
}

func (p *prompter) warn(text string) {
	for _, l := range wrap(text, wrapWidth) {
		p.printf("%s\n", p.s.Yellow(l))
	}
}

// line asks a question. The prompt always ends in "]: ", which the installer
// tests rely on to detect questions.
func (p *prompter) line(question, hint string) (string, error) {
	p.grouped = false
	p.printf("%s %s [%s]: ", p.s.Cyan("?"), p.s.Bold(question), p.s.Dim(hint))
	s, err := p.r.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		p.printf("\n")
		return "", ErrCancelled
	}
	return strings.TrimSpace(s), nil
}

// enter describes what pressing Enter selects: the recommended value, the
// current setting, or a plain default, plus the recommendation when the
// default differs from it.
func (p *prompter) enter(value string, isRecommended bool, recommended string) string {
	s := p.t("enter_is", value)
	switch {
	case isRecommended:
		s += " (" + p.t("recommended") + ")"
	case p.existing:
		s += " (" + p.t("current") + ")"
	}
	if recommended != "" && !isRecommended {
		s += " · " + p.t("recommended_is", recommended)
	}
	return s
}

// word is the answer shown in hints; y/n answers are English everywhere.
func (p *prompter) word(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// yesNo asks a yes/no question; rec is the recommended answer, if any.
func (p *prompter) yesNo(question string, def bool, rec *bool) (bool, error) {
	yn := p.t("yn_default_no")
	if def {
		yn = p.t("yn_default_yes")
	}
	recommended := ""
	if rec != nil && *rec != def {
		recommended = p.word(*rec)
	}
	hint := yn + " · " + p.enter(p.word(def), rec != nil && *rec == def, recommended)
	for {
		s, err := p.line(question, hint)
		if err != nil {
			return false, err
		}
		answer := strings.ToLower(s)
		switch {
		case answer == "":
			return def, nil
		case slices.Contains(i18n.YesWords, answer):
			return true, nil
		case slices.Contains(i18n.NoWords, answer):
			return false, nil
		}
		p.warn(p.t("yesno_retry"))
	}
}

// text returns def on Enter. rec is the recommended value ("" = none); with
// required, an empty answer is refused when there is no default.
func (p *prompter) text(question, def, rec string, required bool) (string, error) {
	var hint string
	if def == "" && required {
		hint = p.t("required")
	} else {
		shown := def
		if shown == "" {
			shown = p.t("none")
		}
		recommended := ""
		if rec != "" && rec != def {
			recommended = rec
		}
		hint = p.enter(shown, rec != "" && rec == def, recommended)
	}
	for {
		s, err := p.line(question, hint)
		if err != nil {
			return "", err
		}
		if s != "" {
			return s, nil
		}
		if def != "" || !required {
			return def, nil
		}
	}
}

// list reads a comma-separated list; Enter keeps def and "-" clears it.
// emptyRecommended marks an empty list as the recommended answer.
func (p *prompter) list(question string, def []string, emptyRecommended bool) ([]string, error) {
	hint := p.t("list_hint") + " · "
	if len(def) == 0 {
		hint += p.enter(p.t("none"), emptyRecommended, "")
	} else {
		hint += p.enter(p.t("list_keep", strings.Join(def, ", ")), false, "") + " · " + p.t("list_clear")
	}
	s, err := p.line(question, hint)
	if err != nil {
		return nil, err
	}
	switch s {
	case "":
		return append([]string{}, def...), nil
	case "-":
		return []string{}, nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out, nil
}

// integer asks for a whole number of at least min; rec is the recommended
// value (0 = none).
func (p *prompter) integer(question string, def, min, rec int) (int, error) {
	recText := ""
	if rec > 0 {
		recText = strconv.Itoa(rec)
	}
	for {
		s, err := p.text(question, strconv.Itoa(def), recText, false)
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(s)
		if err == nil && n >= min {
			return n, nil
		}
		p.warn(p.t("integer_retry", min))
	}
}

// chooseLanguage shows the language menu in all languages and returns the
// chosen code; def is preselected.
func (p *prompter) chooseLanguage(def string) (string, error) {
	var items []string
	defNum := 1
	for i, code := range i18n.Languages {
		items = append(items, fmt.Sprintf("%d) %s", i+1, i18n.Names[code]))
		if code == def {
			defNum = i + 1
		}
	}
	p.printf("%s\n  %s\n", p.s.Title("Language / Язык / Langue"), strings.Join(items, "   "))
	hint := fmt.Sprintf("Enter = %d (%s)", defNum, i18n.Names[i18n.Languages[defNum-1]])
	for {
		s, err := p.line("Language / Язык / Langue", hint)
		if err != nil {
			return "", err
		}
		if s == "" {
			return i18n.Languages[defNum-1], nil
		}
		if code := i18n.Normalize(s); code != "" {
			return code, nil
		}
		p.warn("1 = English, 2 = Русский, 3 = Français")
	}
}

// wrap breaks text into lines of at most width characters; explicit line
// breaks are kept.
func wrap(text string, width int) []string {
	var out []string
	for _, para := range strings.Split(text, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			switch {
			case line == "":
				line = word
			case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width:
				out = append(out, line)
				line = word
			default:
				line += " " + word
			}
		}
		out = append(out, line)
	}
	return out
}

// Terminal returns the interactive input and output for setup. stdin is used
// when it is a terminal; otherwise the controlling terminal is opened, so that
// `curl ... | sh` installers can ask questions while stdin is the script.
func Terminal() (io.Reader, io.Writer, func(), bool) {
	if isTerminal(os.Stdin) {
		return os.Stdin, os.Stdout, func() {}, true
	}
	in, out := "/dev/tty", "/dev/tty"
	if runtime.GOOS == "windows" {
		in, out = "CONIN$", "CONOUT$"
	}
	r, err := os.OpenFile(in, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, func() {}, false
	}
	w, err := os.OpenFile(out, os.O_RDWR, 0)
	if err != nil {
		r.Close()
		return nil, nil, func() {}, false
	}
	return r, w, func() { r.Close(); w.Close() }, true
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
