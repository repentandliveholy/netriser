package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/repentandliveholy/netriser/internal/term"
)

func TestColorLogLine(t *testing.T) {
	on := term.Style{On: true}
	if got := colorLogLine(on, "[2026-11-12 12:03:01] [WARN] check FAILED"); !strings.HasPrefix(got, "\x1b[33m") {
		t.Fatalf("warning not yellow: %q", got)
	}
	if got := colorLogLine(term.Style{}, "[x] [ERROR] boom"); got != "[x] [ERROR] boom" {
		t.Fatalf("colored without terminal: %q", got)
	}
	var buf bytes.Buffer
	lineColorer{&buf, on}.Write([]byte("[a] [RECOVERY] x\n[b] [INFO] y\n"))
	if !strings.Contains(buf.String(), "\x1b[36m[a] [RECOVERY] x\x1b[0m\n[b] [INFO] y\n") {
		t.Fatalf("live colors wrong: %q", buf.String())
	}
}

func TestColorStatus(t *testing.T) {
	report := "Overall Health:       UNHEALTHY (internet=false)\n  [OK] 1.1.1.1:53\n"
	got := colorStatus(term.Style{On: true}, report)
	if !strings.Contains(got, "\x1b[31mOverall Health:") || !strings.Contains(got, "\x1b[32m  [OK]\x1b[0m 1.1.1.1:53") {
		t.Fatalf("status colors wrong: %q", got)
	}
	if colorStatus(term.Style{}, report) != report {
		t.Fatal("colored without terminal")
	}
}
