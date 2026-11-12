package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type relocateFixture struct {
	dir, config     string
	legacy, current map[string]string
}

func newRelocateFixture(t *testing.T) relocateFixture {
	t.Helper()
	dir := t.TempDir()
	oldBase := filepath.Join(dir, "mesh-watchdog")
	newBase := filepath.Join(dir, "netriser")
	return relocateFixture{
		dir:    dir,
		config: filepath.Join(dir, "config.yaml"),
		legacy: map[string]string{
			"state_dir":    filepath.Join(oldBase, "state"),
			"log_file":     filepath.Join(oldBase, "logs", "mesh-watchdog.log"),
			"incident_dir": filepath.Join(oldBase, "logs", "incidents"),
			"lock_file":    filepath.Join(oldBase, "state", "mesh-watchdog.lock"),
		},
		current: map[string]string{
			"state_dir":    filepath.Join(newBase, "state"),
			"log_file":     filepath.Join(newBase, "logs", "netriser.log"),
			"incident_dir": filepath.Join(newBase, "logs", "incidents"),
			"lock_file":    filepath.Join(newBase, "state", "netriser.lock"),
		},
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f relocateFixture) configWith(paths map[string]string) string {
	return "# kept comment\ncheck_interval_sec: 60\n" +
		"state_dir: " + paths["state_dir"] + "\n" +
		"log_file: " + paths["log_file"] + "\n" +
		"incident_dir: " + paths["incident_dir"] + "\n" +
		"lock_file: " + paths["lock_file"] + "\n"
}

func TestRelocateLegacyPathsMovesDataAndSwitchesConfig(t *testing.T) {
	f := newRelocateFixture(t)
	writeFile(t, f.config, f.configWith(f.legacy))
	writeFile(t, filepath.Join(f.legacy["state_dir"], "state.json"), `{"fail_count":0}`)
	writeFile(t, f.legacy["lock_file"], "")
	writeFile(t, f.legacy["log_file"], "old log\n")
	writeFile(t, f.legacy["log_file"]+".1", "rotated\n")
	writeFile(t, filepath.Join(f.legacy["incident_dir"], "inc-1.json"), "{}")

	moved, err := relocateLegacyPaths(f.config, f.legacy, f.current)
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 4 {
		t.Fatalf("moved = %v, want 4 settings", moved)
	}
	if got := readFile(t, filepath.Join(f.current["state_dir"], "state.json")); got != `{"fail_count":0}` {
		t.Fatalf("state not moved: %q", got)
	}
	if got := readFile(t, f.current["log_file"]); got != "old log\n" {
		t.Fatalf("log not moved: %q", got)
	}
	if got := readFile(t, f.current["log_file"]+".1"); got != "rotated\n" {
		t.Fatalf("rotated log not moved: %q", got)
	}
	if _, err := os.Stat(filepath.Join(f.current["incident_dir"], "inc-1.json")); err != nil {
		t.Fatalf("incidents not moved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.current["state_dir"], "mesh-watchdog.lock")); !os.IsNotExist(err) {
		t.Fatalf("old lock file travelled with the state directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "mesh-watchdog")); !os.IsNotExist(err) {
		t.Fatalf("empty legacy directory left behind: %v", err)
	}
	cfg := readFile(t, f.config)
	if !strings.Contains(cfg, "# kept comment") || !strings.Contains(cfg, "check_interval_sec: 60") {
		t.Fatalf("config lost other content:\n%s", cfg)
	}
	for key, want := range f.current {
		if !strings.Contains(cfg, key+": "+want) {
			t.Fatalf("config %s not switched to %s:\n%s", key, want, cfg)
		}
	}
	if strings.Contains(cfg, "mesh-watchdog") {
		t.Fatalf("config still names mesh-watchdog:\n%s", cfg)
	}

	again, err := relocateLegacyPaths(f.config, f.legacy, f.current)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run = %v, %v; want nothing to do", again, err)
	}
}

func TestRelocateLegacyPathsKeepsUserChosenPaths(t *testing.T) {
	f := newRelocateFixture(t)
	custom := map[string]string{
		"state_dir":    filepath.Join(f.dir, "custom", "state"),
		"log_file":     filepath.Join(f.dir, "custom", "app.log"),
		"incident_dir": filepath.Join(f.dir, "custom", "incidents"),
		"lock_file":    filepath.Join(f.dir, "custom", "app.lock"),
	}
	content := f.configWith(custom)
	writeFile(t, f.config, content)
	writeFile(t, custom["log_file"], "mine\n")

	moved, err := relocateLegacyPaths(f.config, f.legacy, f.current)
	if err != nil || len(moved) != 0 {
		t.Fatalf("moved = %v, %v; want nothing", moved, err)
	}
	if got := readFile(t, f.config); got != content {
		t.Fatalf("config changed:\n%s", got)
	}
	if got := readFile(t, custom["log_file"]); got != "mine\n" {
		t.Fatalf("custom log touched: %q", got)
	}
}

func TestRelocateLegacyPathsNeverOverwritesExistingData(t *testing.T) {
	f := newRelocateFixture(t)
	writeFile(t, f.config, f.configWith(f.legacy))
	writeFile(t, filepath.Join(f.legacy["state_dir"], "state.json"), "old")
	writeFile(t, filepath.Join(f.current["state_dir"], "state.json"), "new")
	writeFile(t, f.legacy["log_file"], "old log\n")
	writeFile(t, f.current["log_file"], "new log\n")

	moved, err := relocateLegacyPaths(f.config, f.legacy, f.current)
	if err != nil {
		t.Fatal(err)
	}
	cfg := readFile(t, f.config)
	if !strings.Contains(cfg, "state_dir: "+f.legacy["state_dir"]) || !strings.Contains(cfg, "log_file: "+f.legacy["log_file"]) {
		t.Fatalf("settings with data at both places must keep the old path:\n%s", cfg)
	}
	if got := readFile(t, filepath.Join(f.current["state_dir"], "state.json")); got != "new" {
		t.Fatalf("existing state overwritten: %q", got)
	}
	if got := readFile(t, filepath.Join(f.legacy["state_dir"], "state.json")); got != "old" {
		t.Fatalf("old state lost: %q", got)
	}
	if got := readFile(t, f.current["log_file"]); got != "new log\n" {
		t.Fatalf("existing log overwritten: %q", got)
	}
	for _, line := range moved {
		if strings.HasPrefix(line, "state_dir:") || strings.HasPrefix(line, "log_file:") {
			t.Fatalf("reported a move that did not happen: %v", moved)
		}
	}
}

func TestRelocateLegacyPathsMissingConfig(t *testing.T) {
	f := newRelocateFixture(t)
	moved, err := relocateLegacyPaths(f.config, f.legacy, f.current)
	if err != nil || moved != nil {
		t.Fatalf("moved = %v, %v; want nil, nil", moved, err)
	}
}
