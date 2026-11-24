package install

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded license texts must be the repository's.
func TestLegalCopiesMatchRepository(t *testing.T) {
	for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES"} {
		want, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Legal.ReadFile("legal/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("internal/install/legal/%s differs from %s: cp %s internal/install/legal/", name, name, name)
		}
	}
}

func TestAddToPath(t *testing.T) {
	dir := `C:\Program Files\NetRiser`
	for _, tc := range []struct {
		in, want string
		changed  bool
	}{
		{`C:\Windows\system32;C:\Windows`, `C:\Windows\system32;C:\Windows;` + dir, true},
		{`C:\Windows;c:\program files\netriser\;C:\Tools`, `C:\Windows;c:\program files\netriser\;C:\Tools`, false},
		{``, dir, true},
		{`C:\Windows;;`, `C:\Windows;` + dir, true},
	} {
		got, changed := AddToPath(tc.in, dir)
		if got != tc.want || changed != tc.changed {
			t.Errorf("AddToPath(%q) = %q, %v; want %q, %v", tc.in, got, changed, tc.want, tc.changed)
		}
	}
}

func TestLanguageFromLangID(t *testing.T) {
	for id, want := range map[uint16]string{0x0419: "ru", 0x0423: "ru", 0x040c: "fr", 0x080c: "fr", 0x0409: "en", 0x0407: "en"} {
		if got := LanguageFromLangID(id); got != want {
			t.Errorf("LanguageFromLangID(%#x) = %s, want %s", id, got, want)
		}
	}
}

func TestPrompterAsk(t *testing.T) {
	var out bytes.Buffer
	p := &prompter{in: bufio.NewReader(strings.NewReader("\nn\nmaybe\nда\n")), out: &out, lang: "ru", ok: true}
	if !p.ask("Q1", true) {
		t.Error("Enter must mean yes")
	}
	if p.ask("Q2", true) {
		t.Error("n must mean no")
	}
	if !p.ask("Q3", true) {
		t.Error("an unclear answer must be asked again, then да accepted")
	}
	if !strings.Contains(out.String(), "Enter = да") {
		t.Errorf("prompt not in Russian: %q", out.String())
	}
	none := &prompter{out: &out, ok: false}
	if none.ask("Q", false) || !none.ask("Q", true) {
		t.Error("without a terminal the default must be used")
	}
	if l := (&prompter{in: bufio.NewReader(strings.NewReader("2\n")), out: &out, ok: true}).askLanguage("en"); l != "ru" {
		t.Errorf("language menu: %s", l)
	}
	if l := (&prompter{in: bufio.NewReader(strings.NewReader("\n")), out: &out, ok: true}).askLanguage("fr"); l != "fr" {
		t.Errorf("language default: %s", l)
	}
}
