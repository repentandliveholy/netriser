package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecentLogLinesIncludesRotatedLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netriser.log")
	if err := os.WriteFile(path+".1", []byte("a\nb\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("c\r\nd\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := recentLogLines(path, 3)
	if err != nil || strings.Join(got, ",") != "b,c,d" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, _ = recentLogLines(path, 0)
	if strings.Join(got, ",") != "a,b,c,d" {
		t.Fatalf("all lines: %q", got)
	}
	if _, err := recentLogLines(filepath.Join(dir, "missing.log"), 5); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing log: %v", err)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func appendLog(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func waitFor(t *testing.T, out *syncBuffer, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if out.String() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("output %q, want %q", out.String(), want)
}

func TestFollowLogStreamsNewLinesAcrossRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netriser.log")
	appendLog(t, path, "old line\n")
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- followLog(ctx, path, out, 10*time.Millisecond) }()
	time.Sleep(50 * time.Millisecond)

	appendLog(t, path, "first\nsec")
	waitFor(t, out, "first\n") // partial lines wait for their newline
	appendLog(t, path, "ond\n")
	waitFor(t, out, "first\nsecond\n")

	// Rotation as the service does it: rename, then a new file.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	appendLog(t, path, "after rotation\n")
	waitFor(t, out, "first\nsecond\nafter rotation\n")

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
