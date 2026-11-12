package term

import (
	"bytes"
	"testing"
)

func TestStyle(t *testing.T) {
	if got := (Style{}).Red("x"); got != "x" {
		t.Fatalf("disabled style changed text: %q", got)
	}
	if got := (Style{On: true}).Green("ok"); got != "\x1b[32mok\x1b[0m" {
		t.Fatalf("got %q", got)
	}
	if For(&bytes.Buffer{}).On {
		t.Fatal("colors enabled for a non-terminal writer")
	}
}
