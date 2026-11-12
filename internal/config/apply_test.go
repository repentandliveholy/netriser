package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryExampleMatchesEmbeddedTemplate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(Template) {
		t.Fatal("config.example.yaml differs from internal/config/config.example.yaml; copy it")
	}
}

func TestTemplateIsCompleteAndSafeForNewInstallations(t *testing.T) {
	cfg, err := parse(Template, "template")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ObservationMode || cfg.AllowVPNBypass || cfg.EnableReboot || !cfg.MonitorsService("anything") {
		t.Fatalf("unsafe template defaults: %+v", cfg)
	}
	values, _ := DefaultConfig().Values()
	for key := range values {
		switch key {
		case "log_file", "state_dir", "incident_dir", "lock_file":
			continue // platform defaults
		}
		if !strings.Contains(string(Template), "\n"+key+":") {
			t.Errorf("template does not document %s", key)
		}
	}
}

func TestExistingConfigurationsKeepLegacyBehaviour(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.yaml")
	os.WriteFile(path, []byte("check_interval_sec: 60\n"), 0600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ObservationMode || !cfg.AllowVPNBypass || cfg.MonitorsService("wg-quick@wg0") || !cfg.MonitorsService("tailscaled") {
		t.Fatalf("legacy behaviour changed: %+v", cfg)
	}
}

func TestApplyCreatesFromTemplateAndPreservesUnchangedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "config.yaml")
	cfg, changed, err := Apply(path, map[string]any{
		"observation_mode":           false,
		"canary_targets":             []string{"10.0.0.1:53", "10.0.0.2:53"},
		"allowed_default_interfaces": []string{"wg0"},
		"overlays":                   []OverlayConfig{{Name: "corp", Interface: "^corp[0-9]+$", Kind: "vpn", Services: []string{"corp.service"}}},
	})
	if err != nil || !changed {
		t.Fatalf("apply: %v %v", changed, err)
	}
	if cfg.ObservationMode || len(cfg.CanaryTargets) != 2 || cfg.AllowedDefaultInterfaces[0] != "wg0" || cfg.Overlays[0].Services[0] != "corp.service" {
		t.Fatalf("values not applied: %+v", cfg)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# Observation mode is read-only") || !strings.Contains(string(data), "netriser setup") {
		t.Fatalf("template comments lost:\n%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatalf("new configuration mode %v", info.Mode().Perm())
	}
	if _, changed, err := Apply(path, map[string]any{"observation_mode": false, "canary_targets": []string{"10.0.0.1:53", "10.0.0.2:53"}}); err != nil || changed {
		t.Fatalf("unchanged values rewrote file: %v %v", changed, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("file modified without changes")
	}
}

func TestApplyAbsentLegacyValueIsNotWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.yaml")
	original := "# mine\ncheck_interval_sec: 99 # keep\n"
	os.WriteFile(path, []byte(original), 0640)
	if _, changed, err := Apply(path, map[string]any{"allow_vpn_bypass": true, "observation_mode": false}); err != nil || changed {
		t.Fatalf("legacy-equivalent answers rewrote file: %v %v", changed, err)
	}
	cfg, changed, err := Apply(path, map[string]any{"allow_vpn_bypass": false})
	if err != nil || !changed || cfg.AllowVPNBypass {
		t.Fatalf("apply: %v %v %+v", changed, err, cfg)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# keep") || !strings.Contains(string(data), "allow_vpn_bypass: false") {
		t.Fatalf("comments or value lost:\n%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0640 {
		t.Fatal("existing permissions changed")
	}
}

func TestApplyRejectsInvalidValuesWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(path, []byte("check_interval_sec: 60\n"), 0600)
	for _, values := range []map[string]any{
		{"no_such_setting": true},
		{"overlays": []OverlayConfig{{Name: "x", Interface: "(["}}},
		{"overlays": []OverlayConfig{{Name: "x", Interface: "^x", Kind: "other"}}},
		{"update_public_keys": []string{"nope"}},
		{"check_interval_sec": 0},
	} {
		if _, _, err := Apply(path, values); err == nil {
			t.Errorf("accepted %v", values)
		}
	}
	data, _ := os.ReadFile(path)
	if string(data) != "check_interval_sec: 60\n" {
		t.Fatalf("invalid values written: %s", data)
	}
}
