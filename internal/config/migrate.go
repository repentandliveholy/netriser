package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// MigrateLegacy preserves the settings and durable state of a legacy installation.
// It must be run with the legacy daemon stopped. Explicit configurations are
// updated in place; otherwise the old default configuration is copied to the
// new default location. Existing canonical configurations are never overwritten.
// It reports whether a legacy configuration or state was found and migrated.
func MigrateLegacy(explicit string) (bool, error) {
	if explicit == "" {
		explicit = os.Getenv("CONF_FILE")
	}
	legacy, oldConfig := legacyDefaults()
	return migrateLegacy(explicit, DefaultConfigPath(), oldConfig, legacy)
}

// Retaining legacy paths deliberately keeps reboot budgets, caches, quarantine
// records and the shared lock intact without moving or overwriting state.
func migrateLegacy(explicit, defaultTarget, oldConfig string, legacy map[string]string) (bool, error) {
	target := explicit
	source := explicit
	if target == "" {
		target, source = defaultTarget, oldConfig
		if _, err := os.Stat(target); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	data, err := os.ReadFile(source)
	if os.IsNotExist(err) && explicit == "" {
		if _, stateErr := os.Stat(legacy["state_dir"]); os.IsNotExist(stateErr) {
			return false, nil
		} else if stateErr != nil {
			return false, stateErr
		}
		data = []byte("{}\n")
	} else if err != nil {
		return false, fmt.Errorf("read legacy configuration: %w", err)
	}
	// Validate before modifying the file; this also rejects unknown settings.
	if len(data) > 0 && !(explicit == "" && bytes.Equal(data, []byte("{}\n"))) {
		if _, err := Load(source); err != nil {
			return false, err
		}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &doc); err != nil {
		return false, err
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
		doc.Kind = yaml.DocumentNode
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false, fmt.Errorf("legacy configuration must be a mapping")
	}
	present := map[string]bool{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		present[key.Value] = true
		if key.Value == "update_url" && IsLegacyUpdateURL(value.Value) {
			value.Value = DefaultUpdateURL
		}
	}
	for _, key := range []string{"state_dir", "log_file", "incident_dir", "lock_file", "update_url"} {
		if !present[key] {
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: legacy[key]})
		}
	}
	root.Style = 0
	output, err := yaml.Marshal(&doc)
	if err != nil {
		return false, err
	}
	if err = os.MkdirAll(filepath.Dir(target), 0750); err != nil {
		return false, err
	}
	if explicit == "" {
		f, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return false, e
		}
		_, e = f.Write(output)
		ce := f.Close()
		if e != nil {
			_ = os.Remove(target)
			return false, e
		}
		return ce == nil, ce
	}
	info, err := os.Stat(target)
	if err != nil {
		return false, err
	}
	f, err := os.CreateTemp(filepath.Dir(target), ".netriser-migrate-*")
	if err != nil {
		return false, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(info.Mode().Perm()); err == nil {
		_, err = f.Write(output)
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return false, err
	}
	err = os.Rename(tmp, target)
	return err == nil, err
}

func legacyDefaults() (map[string]string, string) {
	old := map[string]string{"update_url": "https://netriser.repentandliveholy.org"}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		base = filepath.Join(base, "mesh-watchdog")
		old["state_dir"] = filepath.Join(base, "state")
		old["log_file"] = filepath.Join(base, "logs", "mesh-watchdog.log")
		old["incident_dir"] = filepath.Join(base, "logs", "incidents")
		old["lock_file"] = filepath.Join(old["state_dir"], "mesh-watchdog.lock")
		return old, filepath.Join(base, "config.yaml")
	case "darwin":
		old["state_dir"] = "/Library/Application Support/mesh-watchdog"
		old["log_file"] = "/var/log/mesh-watchdog.log"
		old["incident_dir"] = "/var/log/mesh-watchdog/incidents"
		old["lock_file"] = "/var/run/mesh-watchdog.lock"
	default:
		old["state_dir"] = "/var/lib/mesh-watchdog"
		old["log_file"] = "/var/log/mesh-watchdog.log"
		old["incident_dir"] = "/var/log/mesh-watchdog/incidents"
		old["lock_file"] = "/run/mesh-watchdog/mesh-watchdog.lock"
	}
	return old, "/etc/mesh-watchdog/config.yaml"
}
