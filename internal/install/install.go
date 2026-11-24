// Package install implements `netriser install`: the program installs
// itself, so the downloaded or copied netriser.exe is its own installer. On
// Windows it also runs when the file is double-clicked. It needs no network
// access, so it works from a USB drive on a machine that is cut off.
package install

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"strings"

	"github.com/repentandliveholy/netriser/internal/i18n"
	"github.com/repentandliveholy/netriser/internal/term"
)

// Legal holds the license texts installed next to the program. The copies in
// legal/ must equal the repository's LICENSE and THIRD_PARTY_NOTICES
// (enforced by a test).
//
//go:embed legal/LICENSE legal/THIRD_PARTY_NOTICES
var Legal embed.FS

// Options control an installation.
type Options struct {
	// ConfPath is an explicit configuration file (--config).
	ConfPath string
	// Lang is the language chosen with --lang; empty asks.
	Lang string
	// Yes answers every question with its default (--yes).
	Yes bool
	// DoubleClick: started from Explorer; the window waits for Enter at the
	// end so the result can be read.
	DoubleClick bool
	// Version is the version being installed.
	Version string
}

// prompter asks yes/no questions; Enter selects the default (yes).
type prompter struct {
	in   *bufio.Reader
	out  io.Writer
	lang string
	yes  bool // answer everything with the default
	ok   bool // a terminal is available
	s    term.Style
}

func (p *prompter) t(key string, args ...any) string { return i18n.T(p.lang, key, args...) }

func (p *prompter) say(text string) { fmt.Fprintln(p.out, text) }

func (p *prompter) step(key string, args ...any) { p.say(p.s.Cyan(p.t(key, args...))) }

func (p *prompter) good(key string, args ...any) { p.say(p.s.Green(p.t(key, args...))) }

func (p *prompter) warn(key string, args ...any) { p.say(p.s.Yellow(p.t(key, args...))) }

func (p *prompter) bad(key string, args ...any) { p.say(p.s.Red(p.t(key, args...))) }

// ask returns the answer to a yes/no question; Enter means yes. Without a
// terminal it returns def.
func (p *prompter) ask(question string, def bool) bool {
	if p.yes || !p.ok {
		return def
	}
	for {
		fmt.Fprintf(p.out, "%s %s ", p.s.Bold(question), p.t("inst_yn"))
		line, err := p.in.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			if err != nil {
				return def
			}
			return true
		case "y", "yes", "д", "да", "o", "oui":
			return true
		case "n", "no", "н", "нет", "non":
			return false
		}
		if err != nil {
			return def
		}
	}
}

// askLanguage asks for the language once, in all three languages.
func (p *prompter) askLanguage(def string) string {
	if p.yes || !p.ok {
		return def
	}
	idx := map[string]string{"en": "1 (English)", "ru": "2 (Русский)", "fr": "3 (Français)"}[def]
	for {
		fmt.Fprintf(p.out, "Language / Язык / Langue: 1) English  2) Русский  3) Français [Enter = %s] ", idx)
		line, err := p.in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		if l := i18n.Normalize(line); l != "" {
			return l
		}
		if err != nil {
			return def
		}
	}
}

// AddToPath appends dir to a PATH value unless it is already listed
// (case-insensitive, ignoring a trailing backslash).
func AddToPath(path, dir string) (string, bool) {
	want := strings.TrimRight(strings.ToLower(dir), `\`)
	var parts []string
	for _, p := range strings.Split(path, ";") {
		if p == "" {
			continue
		}
		if strings.TrimRight(strings.ToLower(p), `\`) == want {
			return path, false
		}
		parts = append(parts, p)
	}
	return strings.Join(append(parts, dir), ";"), true
}

// LanguageFromLangID maps a Windows language ID to en, ru or fr.
func LanguageFromLangID(id uint16) string {
	switch id & 0x3ff {
	case 0x19, 0x23: // Russian, Belarusian
		return "ru"
	case 0x0c:
		return "fr"
	}
	return "en"
}

// commandWrapper runs the installed program; nr.cmd and mesh-watchdog.cmd
// always call it, so a self-update also updates what the commands run.
const commandWrapper = "@echo off\r\n\"%~dp0netriser.exe\" %*\r\nexit /b %ERRORLEVEL%\r\n"
