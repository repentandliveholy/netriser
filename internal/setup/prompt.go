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

	xterm "golang.org/x/term"

	"github.com/repentandliveholy/netriser/internal/i18n"
	"github.com/repentandliveholy/netriser/internal/term"
)

// ErrCancelled is returned when the user declines to save or input ends.
var ErrCancelled = errors.New("setup cancelled; nothing was changed")

const (
	wrapWidth = 78
	indent    = "      " // aligns answers and help under the question text
)

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
	// sec and q number the questions ("2.3"); lastQ keeps a re-asked
	// question on the same number.
	sec, q int
	lastQ  string
	// arrows enables arrow-key choices on the terminal fd; otherwise answers
	// are typed.
	arrows bool
	fd     int
}

// newPrompter enables arrow-key choices when input and output are terminals
// with colors (NO_COLOR, TERM=dumb or NETRISER_PLAIN=1 select typed answers).
func newPrompter(in io.Reader, out io.Writer, existing bool) *prompter {
	p := &prompter{r: bufio.NewReader(in), w: out, lang: "en", s: term.For(out), existing: existing}
	if f, ok := in.(*os.File); ok && p.s.On && os.Getenv("NETRISER_PLAIN") != "1" && xterm.IsTerminal(int(f.Fd())) {
		p.arrows, p.fd = true, int(f.Fd())
	}
	return p
}

func (p *prompter) t(key string, args ...any) string { return i18n.T(p.lang, key, args...) }

func (p *prompter) printf(format string, args ...any) { fmt.Fprintf(p.w, format, args...) }

// explain prints dimmed, wrapped help text before a question.
func (p *prompter) explain(text string) {
	if !p.grouped {
		p.printf("\n")
	}
	p.grouped = true
	for _, l := range wrap(text, wrapWidth-len(indent)) {
		p.printf("%s%s\n", indent, p.s.Dim(l))
	}
}

// note prints wrapped plain text.
func (p *prompter) note(text string) {
	for _, l := range wrap(text, wrapWidth) {
		p.printf("%s\n", l)
	}
}

func (p *prompter) warn(text string) {
	for _, l := range wrap(text, wrapWidth-len(indent)) {
		p.printf("%s%s\n", indent, p.s.Yellow(l))
	}
}

// heading prints the numbered question line.
func (p *prompter) heading(question string) {
	p.grouped = false
	if question != p.lastQ {
		p.q++
		p.lastQ = question
	}
	num := "?"
	if p.sec > 0 {
		num = fmt.Sprintf("%d.%d", p.sec, p.q)
	}
	p.printf("%s%s%s\n", p.s.Cyan(num), strings.Repeat(" ", max(1, len(indent)-len(num))), p.s.Bold(question))
}

// ask prints the hint line and reads a typed answer. The line always ends
// in "]: ", which the installer tests use to detect questions.
func (p *prompter) ask(hint string) (string, error) {
	p.printf("%s[%s]: ", indent, p.s.Dim(hint))
	s, err := p.r.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		p.printf("\n")
		return "", ErrCancelled
	}
	return strings.TrimSpace(s), nil
}

// line asks a question that is answered by typing.
func (p *prompter) line(question, hint string) (string, error) {
	p.heading(question)
	return p.ask(hint)
}

// tag says whether a value is the recommended one or the current setting.
func (p *prompter) tag(isRecommended bool) string {
	switch {
	case isRecommended:
		return p.t("recommended")
	case p.existing:
		return p.t("current")
	}
	return ""
}

// enter describes what pressing Enter selects, plus the recommendation when
// the default differs from it.
func (p *prompter) enter(value string, isRecommended bool, recommended string) string {
	s := p.t("enter_is", value)
	if tag := p.tag(isRecommended); tag != "" {
		s += " (" + tag + ")"
	}
	if recommended != "" && !isRecommended {
		s += " · " + p.t("recommended_is", recommended)
	}
	return s
}

// option is one choice of a menu; key selects it directly.
type option struct {
	label, note string
	key         byte
}

// choose shows a menu and returns the chosen index. With a terminal, the
// arrow keys, Tab or an option's key move the highlight and Enter confirms;
// otherwise typed answers are parsed by parse.
func (p *prompter) choose(question string, opts []option, def int, plainHint, menuHint, retryKey string, parse func(string) (int, bool)) (int, error) {
	p.heading(question)
	if p.arrows {
		if i, ok, err := p.menu(opts, def, menuHint); ok {
			return i, err
		}
	}
	for {
		s, err := p.ask(plainHint)
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		if i, ok := parse(s); ok {
			return i, nil
		}
		p.warn(p.t(retryKey))
	}
}

// chips renders the options with the selected one highlighted.
func (p *prompter) chips(opts []option, sel int) string {
	var b strings.Builder
	for i, o := range opts {
		text := o.label
		if o.note != "" {
			text += " (" + o.note + ")"
		}
		if i == sel {
			b.WriteString(p.s.Reverse(" ▸ " + text + " "))
		} else {
			b.WriteString("   " + text + " ")
		}
		b.WriteString("  ")
	}
	return b.String()
}

// menu runs the arrow-key menu in raw mode. ok is false when the terminal
// cannot switch to raw mode; the caller then asks for a typed answer.
func (p *prompter) menu(opts []option, sel int, hint string) (int, bool, error) {
	state, err := xterm.MakeRaw(p.fd)
	if err != nil {
		return 0, false, nil
	}
	restored := false
	restore := func() {
		if !restored {
			_ = xterm.Restore(p.fd, state)
			restored = true
		}
	}
	defer restore()

	hintWidth := len(indent) + utf8.RuneCountInString("["+hint+"]: ")
	p.printf("%s%s\r\n%s[%s]: ", indent, p.chips(opts, sel), indent, p.s.Dim(hint))
	redraw := func() {
		// Up to the options line, rewrite it, back to the end of the hint.
		p.printf("\x1b[1A\r\x1b[2K%s%s\x1b[1B\r\x1b[%dC", indent, p.chips(opts, sel), hintWidth)
	}
	for {
		c, err := p.r.ReadByte()
		if err != nil {
			restore()
			p.printf("\n")
			return 0, true, ErrCancelled
		}
		switch c {
		case '\r', '\n':
			if c == '\r' && p.r.Buffered() > 0 {
				if next, _ := p.r.Peek(1); len(next) == 1 && next[0] == '\n' {
					_, _ = p.r.ReadByte()
				}
			}
			p.printf("%s\r\n", p.s.Bold(opts[sel].label))
			return sel, true, nil
		case 3, 4: // Ctrl+C, Ctrl+D
			restore()
			p.printf("\n")
			return 0, true, ErrCancelled
		case '\t':
			sel = (sel + 1) % len(opts)
		case 0x1b:
			b1, _ := p.r.ReadByte()
			b2, _ := p.r.ReadByte()
			if b1 == '[' || b1 == 'O' {
				switch b2 {
				case 'A', 'D':
					sel = (sel + len(opts) - 1) % len(opts)
				case 'B', 'C':
					sel = (sel + 1) % len(opts)
				}
			}
		default:
			lower := c
			if c >= 'A' && c <= 'Z' {
				lower = c + 'a' - 'A'
			}
			for i, o := range opts {
				if o.key == lower {
					sel = i
				}
			}
		}
		redraw()
	}
}

func word(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// yesNo asks a yes/no question; rec is the recommended answer, if any.
// Answers are y/n in every language.
func (p *prompter) yesNo(question string, def bool, rec *bool) (bool, error) {
	opts := []option{{label: "yes", key: 'y'}, {label: "no", key: 'n'}}
	for i, v := range []bool{true, false} {
		if rec != nil && *rec == v {
			opts[i].note = p.t("recommended")
		} else if p.existing && v == def {
			opts[i].note = p.t("current")
		}
	}
	defIdx := 1
	if def {
		defIdx = 0
	}
	yn := p.t("yn_default_no")
	if def {
		yn = p.t("yn_default_yes")
	}
	recommended := ""
	if rec != nil && *rec != def {
		recommended = word(*rec)
	}
	hint := yn + " · " + p.enter(word(def), rec != nil && *rec == def, recommended)
	i, err := p.choose(question, opts, defIdx, hint, p.t("menu_hint"), "yesno_retry", func(s string) (int, bool) {
		switch a := strings.ToLower(s); {
		case slices.Contains(i18n.YesWords, a):
			return 0, true
		case slices.Contains(i18n.NoWords, a):
			return 1, true
		}
		return 0, false
	})
	return i == 0, err
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
	p.heading(question)
	for {
		s, err := p.ask(hint)
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
	var opts []option
	var plain []string
	defIdx := 0
	for i, code := range i18n.Languages {
		opts = append(opts, option{label: i18n.Names[code], key: byte('1' + i)})
		plain = append(plain, fmt.Sprintf("%d) %s", i+1, i18n.Names[code]))
		if code == def {
			defIdx = i
		}
	}
	hint := strings.Join(plain, "   ") + " · " + fmt.Sprintf("Enter = %d (%s)", defIdx+1, i18n.Names[i18n.Languages[defIdx]])
	i, err := p.choose("Language / Язык / Langue", opts, defIdx, hint, "←/→ · 1/2/3 · Enter", "choice_retry", func(s string) (int, bool) {
		code := i18n.Normalize(s)
		return slices.Index(i18n.Languages, code), code != ""
	})
	if err != nil {
		return "", err
	}
	return i18n.Languages[i], nil
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
