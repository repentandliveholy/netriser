package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeFreshInstallationAndPreserveRerun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "config.yaml")
	auto, reboot := false, true
	cfg, err := Initialize(path, &auto, &reboot)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoUpdate || !cfg.EnableReboot || cfg.RecoveryIntervalSec != 15 || cfg.RebootMinOutageSec != 300 {
		t.Fatalf("wrong choices: %+v", cfg)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("configuration permissions: %v %v", info, err)
	}
	before, _ := os.ReadFile(path)
	if _, err := Initialize(path, nil, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("unattended rerun changed configuration")
	}
}

func TestInitializeExistingSettingsCommentsAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.yaml")
	original := "# my configuration\nauto_update: false # manual\nenable_reboot: true\ncheck_interval_sec: 123\nstate_dir: /custom/state\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	on, off := true, false
	cfg, err := Initialize(path, &on, &off)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !cfg.AutoUpdate || cfg.EnableReboot || cfg.CheckIntervalSec != 123 || cfg.StateDir != "/custom/state" || !strings.Contains(string(data), "# manual") || !strings.Contains(string(data), "# my configuration") {
		t.Fatalf("lost settings/comments: %s", data)
	}
	invalid := []byte("unknown_setting: true\n")
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(path, &on, &off); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	data, _ = os.ReadFile(path)
	if string(data) != string(invalid) {
		t.Fatal("invalid configuration overwritten")
	}
}
