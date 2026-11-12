package watchdog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/repentandliveholy/netriser/internal/config"
)

func TestStartStopAndRelocationAreLogged(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.StateDir = dir
	cfg.ObservationMode = false
	logPath := filepath.Join(dir, "netriser.log")
	w := NewWatchdogWithDeps(cfg, nil, nil, nil, NewLogger(logPath, false))
	w.SetConfigPath("/etc/netriser/config.yaml")
	w.SetVersion("1.3.4")

	w.LogRelocated([]string{"log_file: /old.log -> /new.log"}, nil)
	w.LogRelocated(nil, errors.New("disk full"))
	w.LogStarted()
	w.LogStopped()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)
	for _, want := range []string{
		"Moved legacy mesh-watchdog files: log_file: /old.log -> /new.log",
		"Moving legacy mesh-watchdog files failed, the old paths stay in use: disk full",
		"NetRiser 1.3.4 started: configuration /etc/netriser/config.yaml; recovery on; default route: ",
		"NetRiser 1.3.4 stopped.",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("log lacks %q:\n%s", want, log)
		}
	}
}

func TestStartLogNamesObservationMode(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.StateDir = dir
	cfg.ObservationMode = true
	logPath := filepath.Join(dir, "netriser.log")
	w := NewWatchdogWithDeps(cfg, nil, nil, nil, NewLogger(logPath, false))

	w.LogStarted()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if log := string(data); !strings.Contains(log, "NetRiser dev started") || !strings.Contains(log, "observation mode (no recovery actions)") {
		t.Fatalf("unexpected start line:\n%s", log)
	}
}
