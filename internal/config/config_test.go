package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.CanaryTargets) == 0 {
		t.Fatal("expected non-empty CanaryTargets")
	}
	if cfg.CheckInterval() != 60*time.Second {
		t.Fatalf("expected 60s interval, got %v", cfg.CheckInterval())
	}
	if cfg.ProbeTimeout() != 3*time.Second {
		t.Fatalf("expected 3s timeout, got %v", cfg.ProbeTimeout())
	}
	if cfg.EnableReboot != false {
		t.Fatalf("expected enable_reboot to be false by default for safety, got %t", cfg.EnableReboot)
	}
	if cfg.RebootBudgetCount <= 0 {
		t.Fatalf("expected positive reboot budget count")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}
}

func TestDNSSettings(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.AllowDNSRecovery || len(cfg.DNSCanaries) < 2 {
		t.Fatal("DNS recovery must be enabled with independent names")
	}
	for _, bad := range []string{"", "1.1.1.1", "https://example.com", "example.com:53", "white space.test"} {
		cfg.DNSCanaries = []string{bad}
		if err := cfg.Validate(); err == nil {
			t.Errorf("invalid DNS name accepted: %q", bad)
		}
	}
	cfg.DNSCanaries = nil
	if err := cfg.Validate(); err != nil {
		t.Fatal("DNS opt out rejected", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("dns_canaries: []\nallow_dns_recovery: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || len(loaded.DNSCanaries) != 0 || loaded.AllowDNSRecovery {
		t.Fatalf("DNS config not respected: %+v %v", loaded, err)
	}
}

func TestLoadCustomConfig(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "test-config.yaml")

	yamlData := `
canary_targets:
  - "1.0.0.1:53"
  - "8.8.4.4:53"
check_interval_sec: 30
probe_timeout_sec: 2
policy_routing_table: 250
enable_reboot: false
`
	if err := os.WriteFile(confPath, []byte(yamlData), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if len(cfg.CanaryTargets) != 2 || cfg.CanaryTargets[0] != "1.0.0.1:53" {
		t.Fatalf("unexpected canary targets: %v", cfg.CanaryTargets)
	}
	if cfg.CheckIntervalSec != 30 {
		t.Fatalf("expected 30, got %d", cfg.CheckIntervalSec)
	}
	if cfg.PolicyRoutingTable != 250 {
		t.Fatalf("expected table 250, got %d", cfg.PolicyRoutingTable)
	}
	if cfg.EnableReboot != false {
		t.Fatalf("expected enable_reboot false")
	}
}

func TestLoadExplicitMissingFileReturnsError(t *testing.T) {
	_, err := Load("/path/to/definitely/nonexistent/file.yaml")
	if err == nil {
		t.Fatal("expected error when explicit config path does not exist")
	}
	if !strings.Contains(err.Error(), "configuration file not found") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestLoadRejectsUnknownYAMLFields(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "unknown-fields.yaml")

	yamlData := `
canary_targets:
  - "1.1.1.1:53"
unknown_field_foo: "bad_value"
`
	if err := os.WriteFile(confPath, []byte(yamlData), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(confPath)
	if err == nil {
		t.Fatal("expected error on unknown YAML field")
	}
	if !strings.Contains(err.Error(), "unknown_field_foo") && !strings.Contains(err.Error(), "field") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(c *Config)
		errSubstr string
	}{
		{
			name: "non-positive interval",
			mutate: func(c *Config) {
				c.CheckIntervalSec = 0
			},
			errSubstr: "check_interval_sec must be positive",
		},
		{
			name: "non-positive probe timeout",
			mutate: func(c *Config) {
				c.ProbeTimeoutSec = -1
			},
			errSubstr: "probe_timeout_sec must be positive",
		},
		{
			name: "no canaries",
			mutate: func(c *Config) {
				c.CanaryTargets = nil
				c.HTTPFallbackURL = ""
				c.MeshCanaries = nil
			},
			errSubstr: "at least one canary target",
		},
		{
			name: "invalid http fallback url",
			mutate: func(c *Config) {
				c.HTTPFallbackURL = "ftp://invalid-url"
			},
			errSubstr: "http_fallback_url must be a valid http or https URL",
		},
		{
			name: "invalid canary host port",
			mutate: func(c *Config) {
				c.CanaryTargets = []string{"invalid:port:extra"}
			},
			errSubstr: "invalid host:port",
		},
		{
			name: "out of order thresholds",
			mutate: func(c *Config) {
				c.FailThresholdStage1 = 5
				c.FailThresholdStage2 = 3
			},
			errSubstr: "cannot be less than fail_threshold_stage1",
		},
		{
			name: "invalid policy table",
			mutate: func(c *Config) {
				c.PolicyRoutingTable = 254 // reserved main table
			},
			errSubstr: "policy_routing_table must be between 1 and 252",
		},
		{
			name: "invalid management gateway",
			mutate: func(c *Config) {
				c.ManagementGateway = "not-an-ip"
			},
			errSubstr: "management_gateway must be a valid IPv4 address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
			}
		})
	}
}

func TestLoadConfigWithBOM(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "bom-config.yaml")

	// Prepend UTF-8 BOM \xef\xbb\xbf
	bomData := append([]byte("\xef\xbb\xbf"), []byte("check_interval_sec: 45\nenable_reboot: false\n")...)
	if err := os.WriteFile(confPath, bomData, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("expected config with UTF-8 BOM to load cleanly, got error: %v", err)
	}
	if cfg.CheckIntervalSec != 45 {
		t.Fatalf("expected interval 45, got %d", cfg.CheckIntervalSec)
	}
	if cfg.EnableReboot != false {
		t.Fatalf("expected enable_reboot to be false, got %t", cfg.EnableReboot)
	}
}

func TestLoadConfigWithCorruptedControlCharacters(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "corrupted-control-chars.yaml")

	// Include byte sequence \xc3\xa2\xc2\x80\xc2\x94 which previously crashed yaml parser with 'control characters are not allowed'
	corrupted := "# Corrupted comment \xc3\xa2\xc2\x80\xc2\x94 text\ncheck_interval_sec: 50\nenable_reboot: false\n"
	if err := os.WriteFile(confPath, []byte(corrupted), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("expected config with control chars to load cleanly after sanitization, got error: %v", err)
	}
	if cfg.CheckIntervalSec != 50 {
		t.Fatalf("expected interval 50, got %d", cfg.CheckIntervalSec)
	}
	if cfg.EnableReboot != false {
		t.Fatalf("expected enable_reboot to be false, got %t", cfg.EnableReboot)
	}
}

func TestSetRebootEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "toggle-config.yaml")

	initial := "# Header comment\ncheck_interval_sec: 60\nenable_reboot: false\n# Footer comment\n"
	if err := os.WriteFile(confPath, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Enable reboot
	if err := SetRebootEnabled(confPath, true); err != nil {
		t.Fatalf("SetRebootEnabled true failed: %v", err)
	}

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("failed to load modified config: %v", err)
	}
	if !cfg.EnableReboot {
		t.Fatal("expected enable_reboot to be true")
	}

	// Verify comments were preserved
	raw, _ := os.ReadFile(confPath)
	if !strings.Contains(string(raw), "# Header comment") || !strings.Contains(string(raw), "# Footer comment") {
		t.Fatal("comments were not preserved in config file")
	}

	// 2. Disable reboot
	if err := SetRebootEnabled(confPath, false); err != nil {
		t.Fatalf("SetRebootEnabled false failed: %v", err)
	}

	cfg2, err := Load(confPath)
	if err != nil {
		t.Fatalf("failed to load modified config: %v", err)
	}
	if cfg2.EnableReboot {
		t.Fatal("expected enable_reboot to be false")
	}
}

func TestAutoUpdateDefaultsAndPersistentToggle(t *testing.T) {
	for _, initial := range []string{
		"# legacy configuration\ncheck_interval_sec: 60\n",
		"# comment\nauto_update: false # keep this comment\nmanagement_interface: eth0\n",
		"{auto_update: false, management_interface: eth0}\n",
		"'auto_update': false\nmanagement_interface: eth0\n",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
			t.Fatal(err)
		}
		for _, enabled := range []bool{false, true, false} {
			if err := SetAutoUpdateEnabled(path, enabled); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil || cfg.AutoUpdate != enabled {
				t.Fatalf("toggle failed: %+v %v", cfg, err)
			}
			if strings.Contains(initial, "eth0") && cfg.ManagementInterface != "eth0" {
				t.Fatal("changed WAN config")
			}
			raw, _ := os.ReadFile(path)
			if strings.Contains(initial, "# keep this comment") && !strings.Contains(string(raw), "# keep this comment") {
				t.Fatal("comment lost")
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatal("config permissions changed")
			}
		}
	}
	path := filepath.Join(t.TempDir(), "new.yaml")
	if err := SetAutoUpdateEnabled(path, false); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.AutoUpdate || cfg.EnableReboot {
		t.Fatalf("unsafe fresh config %+v %v", cfg, err)
	}
	legacy := filepath.Join(t.TempDir(), "legacy.yaml")
	os.WriteFile(legacy, []byte("check_interval_sec: 60\n"), 0644)
	cfg, err = Load(legacy)
	if err != nil || !cfg.AutoUpdate || cfg.AutoUpdateIntervalSec != 21600 {
		t.Fatalf("bad defaults %+v %v", cfg, err)
	}
}

func TestInvalidAutomaticUpdateSettings(t *testing.T) {
	for _, interval := range []int{-1, 0, 59, 2592001} {
		cfg := DefaultConfig()
		cfg.AutoUpdateIntervalSec = interval
		if cfg.Validate() == nil {
			t.Errorf("accepted interval %d", interval)
		}
	}
	for _, url := range []string{"", "http://example.com", "https://"} {
		cfg := DefaultConfig()
		cfg.UpdateURL = url
		if cfg.Validate() == nil {
			t.Errorf("accepted automatic update URL %q", url)
		}
	}
}
