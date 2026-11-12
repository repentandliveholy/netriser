package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// ErrCancelled is returned when the user declines to save or input ends.
var ErrCancelled = errors.New("setup cancelled; nothing was changed")

type prompter struct {
	r *bufio.Reader
	w io.Writer
}

func (p *prompter) printf(format string, args ...any) { fmt.Fprintf(p.w, format, args...) }

func (p *prompter) line(question, hint string) (string, error) {
	p.printf("%s [%s]: ", question, hint)
	s, err := p.r.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		p.printf("\n")
		return "", ErrCancelled
	}
	return strings.TrimSpace(s), nil
}

func (p *prompter) yesNo(question string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		s, err := p.line(question, hint)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		p.printf("Please answer y or n (or Enter for the default).\n")
	}
}

// text returns def on Enter.
func (p *prompter) text(question, def string) (string, error) {
	hint := "Enter = " + def
	if def == "" {
		hint = "Enter = none"
	}
	s, err := p.line(question, hint)
	if err != nil || s == "" {
		return def, err
	}
	return s, nil
}

// list reads a comma-separated list; Enter keeps def and "-" clears it.
func (p *prompter) list(question string, def []string) ([]string, error) {
	hint := "comma separated, Enter = keep " + strings.Join(def, ", ") + ", - = none"
	if len(def) == 0 {
		hint = "comma separated, Enter = none"
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

func (p *prompter) integer(question string, def, min int) (int, error) {
	for {
		s, err := p.text(question, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(s)
		if err == nil && n >= min {
			return n, nil
		}
		p.printf("Please enter a whole number of at least %d.\n", min)
	}
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
