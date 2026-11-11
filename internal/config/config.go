package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Probing targets
	CanaryTargets    []string `yaml:"canary_targets"`
	HTTPFallbackURL  string   `yaml:"http_fallback_url"`
	MeshCanaries     []string `yaml:"mesh_canaries"`
	DNSCanaries      []string `yaml:"dns_canaries"`
	AllowDNSRecovery bool     `yaml:"allow_dns_recovery"`
	// Internet connectivity requires this many distinct successful internet
	// probes (canary_targets plus http_fallback_url), capped at the number
	// configured. A single answering resolver can be a false positive: a VPN
	// kill-switch, for example, still permits DNS to the tunnel's DNS servers.
	MinHealthyTargets int `yaml:"min_healthy_targets"`

	// Timing
	CheckIntervalSec    int `yaml:"check_interval_sec"`
	RecoveryIntervalSec int `yaml:"recovery_interval_sec"`
	ProbeTimeoutSec     int `yaml:"probe_timeout_sec"`

	// Physical network overrides (empty = auto-detect)
	ManagementInterface string `yaml:"management_interface"`
	ManagementGateway   string `yaml:"management_gateway"`

	// Linux policy routing settings
	PolicyRoutingTable    int `yaml:"policy_routing_table"`
	PolicyRoutingPriority int `yaml:"policy_routing_priority"`

	// Monitored overlay services
	MonitoredServices []string `yaml:"monitored_services"`

	// Escalation thresholds (consecutive failures)
	FailThresholdStage1       int `yaml:"fail_threshold_stage1"`
	FailThresholdStage2       int `yaml:"fail_threshold_stage2"`
	FailThresholdStage3       int `yaml:"fail_threshold_stage3"`
	FailThresholdStage4Reboot int `yaml:"fail_threshold_stage4_reboot"`

	// Operational modes & action permissions
	ObservationMode          bool     `yaml:"observation_mode"`
	AllowRouteSanitation     bool     `yaml:"allow_route_sanitation"`
	AllowServiceQuarantine   bool     `yaml:"allow_service_quarantine"`
	AllowNetworkRestart      bool     `yaml:"allow_network_restart"`
	AllowedDefaultInterfaces []string `yaml:"allowed_default_interfaces"`

	// Emergency reboot settings
	EnableReboot          bool `yaml:"enable_reboot"`
	RebootMinOutageSec    int  `yaml:"reboot_min_outage_sec"`
	RebootGraceSec        int  `yaml:"reboot_grace_sec"`
	RebootBudgetCount     int  `yaml:"reboot_budget_count"`
	RebootBudgetWindowSec int  `yaml:"reboot_budget_window_sec"`
	StartupGraceSec       int  `yaml:"startup_grace_sec"`
	EnableSysRqFallback   bool `yaml:"enable_sysrq_fallback"`

	// Paths
	LogFile     string `yaml:"log_file"`
	StateDir    string `yaml:"state_dir"`
	IncidentDir string `yaml:"incident_dir"`
	LockFile    string `yaml:"lock_file"`

	// Update settings
	UpdateURL             string `yaml:"update_url"`
	AutoUpdate            bool   `yaml:"auto_update"`
	AutoUpdateIntervalSec int    `yaml:"auto_update_interval_sec"`
}

// DefaultConfig returns safe defaults tailored for the host OS.
func DefaultConfig() *Config {
	cfg := &Config{
		CanaryTargets: []string{
			"1.1.1.1:53",
			"8.8.8.8:53",
			"9.9.9.9:53",
		},
		HTTPFallbackURL:       "http://1.1.1.1",
		DNSCanaries:           []string{"example.com", "iana.org"},
		AllowDNSRecovery:      true,
		MinHealthyTargets:     2,
		MeshCanaries:          []string{},
		CheckIntervalSec:      60,
		RecoveryIntervalSec:   15,
		ProbeTimeoutSec:       3,
		ManagementInterface:   "",
		ManagementGateway:     "",
		PolicyRoutingTable:    200,
		PolicyRoutingPriority: 100,
		MonitoredServices: []string{
			"netbird",
			"netbird-client",
			"zerotier-one",
			"nebula",
			"tailscaled",
		},
		FailThresholdStage1:       1,
		FailThresholdStage2:       2,
		FailThresholdStage3:       3,
		FailThresholdStage4Reboot: 5,
		ObservationMode:           false,
		AllowRouteSanitation:      true,
		AllowServiceQuarantine:    true,
		AllowNetworkRestart:       true,
		EnableReboot:              false, // Safe default: disabled by default
		RebootMinOutageSec:        300,
		RebootGraceSec:            15,
		RebootBudgetCount:         1,    // Max 1 reboot per window
		RebootBudgetWindowSec:     3600, // 1 hour window
		StartupGraceSec:           60,   // Wait 60s after startup before allowing reboot
		EnableSysRqFallback:       false,
		UpdateURL:                 "https://netriser.repentandliveholy.org",
		AutoUpdate:                true,
		AutoUpdateIntervalSec:     21600,
	}

	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		base := filepath.Join(programData, "netriser")
		cfg.StateDir = filepath.Join(base, "state")
		cfg.LogFile = filepath.Join(base, "logs", "netriser.log")
		cfg.IncidentDir = filepath.Join(base, "logs", "incidents")
		cfg.LockFile = filepath.Join(cfg.StateDir, "netriser.lock")
	case "darwin":
		cfg.StateDir = "/Library/Application Support/netriser"
		cfg.LogFile = "/var/log/netriser.log"
		cfg.IncidentDir = "/var/log/netriser/incidents"
		cfg.LockFile = "/var/run/netriser.lock"
	default: // linux / bsd
		cfg.StateDir = "/var/lib/netriser"
		cfg.LogFile = "/var/log/netriser.log"
		cfg.IncidentDir = "/var/log/netriser/incidents"
		cfg.LockFile = "/run/netriser/netriser.lock"
	}

	return cfg
}

// DefaultConfigPath returns default configuration file path based on OS.
func DefaultConfigPath() string {
	if envPath := os.Getenv("CONF_FILE"); envPath != "" {
		return envPath
	}
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "netriser", "config.yaml")
	default:
		return "/etc/netriser/config.yaml"
	}
}

// Validate performs strict validation of the configuration parameters.
func (c *Config) Validate() error {
	if c.RecoveryIntervalSec <= 0 {
		return fmt.Errorf("recovery_interval_sec must be positive")
	}
	if c.RebootMinOutageSec < 0 {
		return fmt.Errorf("reboot_min_outage_sec must not be negative")
	}
	if c.CheckIntervalSec <= 0 {
		return fmt.Errorf("check_interval_sec must be positive, got %d", c.CheckIntervalSec)
	}
	if c.MinHealthyTargets < 1 {
		return fmt.Errorf("min_healthy_targets must be at least 1, got %d", c.MinHealthyTargets)
	}
	if c.ProbeTimeoutSec <= 0 {
		return fmt.Errorf("probe_timeout_sec must be positive, got %d", c.ProbeTimeoutSec)
	}

	// At least one valid canary target or HTTPFallbackURL required
	if len(c.CanaryTargets) == 0 && c.HTTPFallbackURL == "" && len(c.MeshCanaries) == 0 {
		return errors.New("at least one canary target (canary_targets, http_fallback_url, or mesh_canaries) must be specified")
	}

	// Validate HTTP fallback URL format if present
	if c.HTTPFallbackURL != "" {
		u, err := url.Parse(c.HTTPFallbackURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("http_fallback_url must be a valid http or https URL, got %q", c.HTTPFallbackURL)
		}
	}

	// Validate canary target formats
	for _, target := range c.CanaryTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			return errors.New("empty target found in canary_targets")
		}
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			continue
		}
		host := target
		if strings.Contains(target, ":") {
			var err error
			host, _, err = net.SplitHostPort(target)
			if err != nil {
				return fmt.Errorf("invalid host:port in canary_targets %q: %w", target, err)
			}
		}
		if net.ParseIP(host) == nil && host == "" {
			return fmt.Errorf("invalid host or IP address in canary_targets: %q", target)
		}
	}

	for _, name := range c.DNSCanaries {
		if len(name) > 253 || !strings.Contains(name, ".") || net.ParseIP(name) != nil ||
			!regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9.]$`).MatchString(name) {
			return fmt.Errorf("dns_canaries must contain DNS hostnames, got %q", name)
		}
	}

	// Validate management gateway override if set
	if c.ManagementGateway != "" {
		if ip := net.ParseIP(c.ManagementGateway); ip == nil || ip.To4() == nil {
			return fmt.Errorf("management_gateway must be a valid IPv4 address, got %q", c.ManagementGateway)
		}
	}

	// Validate escalation thresholds: 0 < Stage1 <= Stage2 <= Stage3 <= Stage4Reboot
	if c.FailThresholdStage1 <= 0 {
		return fmt.Errorf("fail_threshold_stage1 must be positive, got %d", c.FailThresholdStage1)
	}
	if c.FailThresholdStage2 < c.FailThresholdStage1 {
		return fmt.Errorf("fail_threshold_stage2 (%d) cannot be less than fail_threshold_stage1 (%d)", c.FailThresholdStage2, c.FailThresholdStage1)
	}
	if c.FailThresholdStage3 < c.FailThresholdStage2 {
		return fmt.Errorf("fail_threshold_stage3 (%d) cannot be less than fail_threshold_stage2 (%d)", c.FailThresholdStage3, c.FailThresholdStage2)
	}
	if c.FailThresholdStage4Reboot < c.FailThresholdStage3 {
		return fmt.Errorf("fail_threshold_stage4_reboot (%d) cannot be less than fail_threshold_stage3 (%d)", c.FailThresholdStage4Reboot, c.FailThresholdStage3)
	}

	// Validate Linux routing table and priority ranges
	if c.PolicyRoutingTable <= 0 || c.PolicyRoutingTable > 252 {
		return fmt.Errorf("policy_routing_table must be between 1 and 252, got %d", c.PolicyRoutingTable)
	}
	if c.PolicyRoutingPriority <= 0 || c.PolicyRoutingPriority >= 32766 {
		return fmt.Errorf("policy_routing_priority must be between 1 and 32765, got %d", c.PolicyRoutingPriority)
	}

	// Validate reboot parameters
	if c.RebootGraceSec < 0 {
		return fmt.Errorf("reboot_grace_sec cannot be negative, got %d", c.RebootGraceSec)
	}
	if c.RebootBudgetCount <= 0 {
		return fmt.Errorf("reboot_budget_count must be positive, got %d", c.RebootBudgetCount)
	}
	if c.RebootBudgetWindowSec <= 0 {
		return fmt.Errorf("reboot_budget_window_sec must be positive, got %d", c.RebootBudgetWindowSec)
	}
	if c.StartupGraceSec < 0 {
		return fmt.Errorf("startup_grace_sec cannot be negative, got %d", c.StartupGraceSec)
	}

	if c.AutoUpdateIntervalSec < 60 || c.AutoUpdateIntervalSec > 30*24*3600 {
		return fmt.Errorf("auto_update_interval_sec must be between 60 and 2592000")
	}
	if c.AutoUpdate && c.UpdateURL == "" {
		return fmt.Errorf("update_url is required when auto_update is enabled")
	}
	if c.AutoUpdate {
		u, err := url.Parse(c.UpdateURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("auto_update requires an HTTPS update_url")
		}
	}
	if c.UpdateURL != "" && !strings.HasPrefix(c.UpdateURL, "http://") && !strings.HasPrefix(c.UpdateURL, "https://") {
		return fmt.Errorf("update_url must start with http:// or https://, got %q", c.UpdateURL)
	}

	return nil
}

// Load loads configuration from path or falls back to defaults.
// If an explicit path is provided and does not exist, an error is returned.
// Unknown YAML fields are strictly rejected.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	explicitPath := path != ""

	if path == "" {
		path = DefaultConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if explicitPath {
				return nil, fmt.Errorf("configuration file not found: %s", path)
			}
			// Default path missing -> safe fallback to defaults
			return cfg, nil
		}
		return nil, fmt.Errorf("error reading configuration file %s: %w", path, err)
	}

	// Strip UTF-8 BOM if present (common on Windows / PowerShell)
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	data = sanitizeYAML(data)

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("error parsing configuration file %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation error: %w", err)
	}

	return cfg, nil
}

// sanitizeYAML replaces invalid control characters that are forbidden by YAML 1.2
// (e.g. C0 control characters other than \t, \n, \r, and C1 control sequences like U+0080..U+009F).
func sanitizeYAML(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		b := data[i]
		// Check for UTF-8 C1 controls: 0xC2 followed by 0x80..0x9F
		if b == 0xc2 && i+1 < len(data) && data[i+1] >= 0x80 && data[i+1] <= 0x9f {
			out = append(out, '-')
			i++ // skip next byte
			continue
		}
		// Check for ASCII control chars (except \t = 9, \n = 10, \r = 13)
		if (b < 32 && b != 9 && b != 10 && b != 13) || b == 127 {
			out = append(out, ' ')
			continue
		}
		out = append(out, b)
	}
	return out
}

// IsAllowedDefaultInterface checks whether an overlay interface is authorized to have default route (e.g. exit-node).
func (c *Config) IsAllowedDefaultInterface(name string) bool {
	for _, iface := range c.AllowedDefaultInterfaces {
		if iface == name {
			return true
		}
	}
	return false
}

// EnsureDirectories ensures that state, log, and incident directories exist.
func (c *Config) EnsureDirectories() error {
	dirs := []string{c.StateDir, c.IncidentDir, filepath.Dir(c.LogFile), filepath.Dir(c.LockFile)}
	for _, d := range dirs {
		if d == "" || d == "." {
			continue
		}
		if err := os.MkdirAll(d, 0750); err != nil {
			if !os.IsPermission(err) {
				return err
			}
		}
	}
	return nil
}

// ProbeTimeout returns duration for canary probes.
// InternetQuorum returns how many distinct internet probes must succeed, given
// the number of internet probes configured.
func (c *Config) InternetQuorum(probes int) int {
	q := c.MinHealthyTargets
	if q < 1 {
		q = 1
	}
	if probes > 0 && q > probes {
		q = probes
	}
	return q
}

func (c *Config) ProbeTimeout() time.Duration {
	if c.ProbeTimeoutSec <= 0 {
		return 3 * time.Second
	}
	return time.Duration(c.ProbeTimeoutSec) * time.Second
}

// SetRebootEnabled updates the enable_reboot setting in the configuration file,
// preserving comments and formatting. If path is empty, it uses DefaultConfigPath().
func SetRebootEnabled(path string, enabled bool) error {
	return setBoolSetting(path, "enable_reboot", enabled)
}

// SetAutoUpdateEnabled preserves the rest of the YAML document and comments.
func SetAutoUpdateEnabled(path string, enabled bool) error {
	return setBoolSetting(path, "auto_update", enabled)
}

// SetObservationMode switches between log-only operation and active recovery.
func SetObservationMode(path string, enabled bool) error {
	return setBoolSetting(path, "observation_mode", enabled)
}

func applyBoolSetting(cfg *Config, key string, enabled bool) {
	switch key {
	case "auto_update":
		cfg.AutoUpdate = enabled
	case "observation_mode":
		cfg.ObservationMode = enabled
	default:
		cfg.EnableReboot = enabled
	}
}

func setBoolSetting(path, key string, enabled bool) error {
	if path == "" {
		path = DefaultConfigPath()
	}

	targetValue := "false"
	if enabled {
		targetValue = "true"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Write fresh default config with requested setting
			dir := filepath.Dir(path)
			if err := os.MkdirAll(dir, 0755); err != nil && !os.IsPermission(err) {
				return err
			}
			fresh := DefaultConfig()
			applyBoolSetting(fresh, key, enabled)
			freshConfig, err := yaml.Marshal(fresh)
			if err != nil {
				return err
			}
			return os.WriteFile(path, []byte(freshConfig), 0644)
		}
		return fmt.Errorf("error reading configuration file %s: %w", path, err)
	}

	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	content := string(sanitizeYAML(data))

	// Validate before writing and handle YAML booleans beyond literal true/false.
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		return err
	}
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	applyBoolSetting(cfg, key, enabled)
	if err := cfg.Validate(); err != nil {
		return err
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:[^\r\n]*`)
	if re.MatchString(content) {
		content = re.ReplaceAllStringFunc(content, func(line string) string {
			comment := ""
			if i := strings.Index(line, "#"); i >= 0 {
				comment = " " + line[i:]
			}
			return key + ": " + targetValue + comment
		})
	} else {
		// Flow mappings, quoted keys and indented documents need a YAML node edit.
		if len(document.Content) == 0 {
			document.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
		}
		mapping := document.Content[0]
		if mapping.Kind != yaml.MappingNode {
			return fmt.Errorf("configuration must be a YAML mapping")
		}
		found := false
		for i := 0; i < len(mapping.Content); i += 2 {
			if mapping.Content[i].Value == key {
				value := mapping.Content[i+1]
				value.Kind, value.Tag, value.Value, value.Style = yaml.ScalarNode, "!!bool", targetValue, 0
				found = true
			}
		}
		if !found {
			mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: targetValue})
		}
		encoded, err := yaml.Marshal(&document)
		if err != nil {
			return err
		}
		content = string(encoded)
	}
	// Never expose a partially written config to the daemon's reload loop.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}

	return nil
}

// CheckInterval returns duration for watchdog ticker.
func (c *Config) CheckInterval() time.Duration {
	if c.CheckIntervalSec <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.CheckIntervalSec) * time.Second
}
