package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateExplicitPreservesSettingsAndStatePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "custom-state")
	original := []byte("# preserve settings\nenable_reboot: true\nauto_update: false\nstate_dir: " + state + "\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacy(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := legacyDefaults()
	if !cfg.EnableReboot || cfg.AutoUpdate || cfg.StateDir != state || cfg.LockFile != legacy["lock_file"] || cfg.UpdateURL != legacy["update_url"] {
		t.Fatalf("migration lost settings: %+v", cfg)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = MigrateLegacy(path); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(second) {
		t.Fatal("migration is not idempotent")
	}
}

func TestMigrateRejectsInvalidConfigWithoutChangingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("unknown_setting: true\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacy(path); err == nil {
		t.Fatal("expected validation failure")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatal("invalid configuration was modified")
	}
}

func TestMigrateUpdaterURL(t *testing.T) {
	for _, tt := range []struct{ input, want string }{
		{"https://mesh-watchdog.repentandliveholy.org", "https://netriser.repentandliveholy.org"},
		{"https://updates.example.com", "https://updates.example.com"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("update_url: "+tt.input+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := MigrateLegacy(path); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.UpdateURL != tt.want {
				t.Fatalf("got %q, want %q", cfg.UpdateURL, tt.want)
			}
		})
	}
}

func TestMigrateDefaultWithoutConfigRetainsLegacyState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "old-state")
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(state, "reboot_history.json")
	if err := os.WriteFile(marker, []byte("history"), 0600); err != nil {
		t.Fatal(err)
	}
	old, _ := legacyDefaults()
	old["state_dir"] = state
	target := filepath.Join(dir, "new", "config.yaml")
	source := filepath.Join(dir, "old", "config.yaml")
	if migrated, err := migrateLegacy("", target, source, old); err != nil || !migrated {
		t.Fatalf("migrated=%v err=%v", migrated, err)
	}
	cfg, err := Load(target)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != state || cfg.LockFile != old["lock_file"] {
		t.Fatalf("state or lock path changed: %+v", cfg)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "history" {
		t.Fatalf("state changed: %q, %v", data, err)
	}
	if err := os.WriteFile(target, []byte("auto_update: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if migrated, err := migrateLegacy("", target, source, old); err != nil || migrated {
		t.Fatalf("migrated=%v err=%v", migrated, err)
	}
	data, err = os.ReadFile(target)
	if err != nil || string(data) != "auto_update: false\n" {
		t.Fatalf("existing destination changed: %q, %v", data, err)
	}
}

func TestMigrateDefaultCopiesLegacySettings(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "old.yaml")
	target := filepath.Join(dir, "new", "config.yaml")
	input := []byte("enable_reboot: true\nauto_update: false\ncheck_interval_sec: 31\nmanagement_interface: eth9\ncanary_targets: [9.9.9.9:53]\n")
	if err := os.WriteFile(source, input, 0600); err != nil {
		t.Fatal(err)
	}
	old, _ := legacyDefaults()
	if _, err := migrateLegacy("", target, source, old); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(target)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EnableReboot || cfg.AutoUpdate || cfg.CheckIntervalSec != 31 || cfg.ManagementInterface != "eth9" || len(cfg.CanaryTargets) != 1 || cfg.CanaryTargets[0] != "9.9.9.9:53" || cfg.StateDir != old["state_dir"] {
		t.Fatalf("legacy settings changed: %+v", cfg)
	}
	after, err := os.ReadFile(source)
	if err != nil || string(after) != string(input) {
		t.Fatalf("source changed: %q, %v", after, err)
	}
}
