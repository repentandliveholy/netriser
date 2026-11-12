package config

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"gopkg.in/yaml.v3"
)

// Template is the commented configuration used for new installations. The
// repository's config.example.yaml is a copy (enforced by a test).
//
//go:embed config.example.yaml
var Template []byte

// Initialize creates a complete configuration on a fresh installation. Existing
// files, comments, paths and settings are preserved unless explicitly selected.
func Initialize(path string, autoUpdate, reboot, observation *bool) (*Config, error) {
	values := map[string]any{}
	if autoUpdate != nil {
		values["auto_update"] = *autoUpdate
	}
	if reboot != nil {
		values["enable_reboot"] = *reboot
	}
	if observation != nil {
		values["observation_mode"] = *observation
	}
	cfg, _, err := Apply(path, values)
	return cfg, err
}

// Apply sets configuration keys, creating the file from Template when it does
// not exist. Comments and unrelated settings are preserved, the result is
// validated before it replaces the file, and a file is left byte-for-byte
// untouched when no effective value changes.
func Apply(path string, values map[string]any) (*Config, bool, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	data, err := os.ReadFile(path)
	fresh := os.IsNotExist(err)
	if fresh {
		data = Template
	} else if err != nil {
		return nil, false, fmt.Errorf("read configuration %s: %w", path, err)
	}
	current, err := parse(data, path)
	if err != nil {
		return nil, false, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(sanitizeYAML(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))), &doc); err != nil {
		return nil, false, err
	}
	if len(doc.Content) == 0 {
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	mapping := doc.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("configuration must be a YAML mapping")
	}

	effective, err := asMap(current)
	if err != nil {
		return nil, false, err
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	changed := fresh
	for _, key := range keys {
		old, known := effective[key]
		if !known {
			return nil, false, fmt.Errorf("unknown configuration setting %q", key)
		}
		want, err := normalize(values[key])
		if err != nil {
			return nil, false, err
		}
		if reflect.DeepEqual(old, want) {
			// Already effective, possibly as a default or legacy value.
			continue
		}
		if err := setKey(mapping, key, values[key]); err != nil {
			return nil, false, err
		}
		changed = true
	}
	if !changed {
		return current, false, nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, false, err
	}
	_ = enc.Close()
	cfg, err := parse(buf.Bytes(), path)
	if err != nil {
		return nil, false, err
	}
	if err := writeAtomic(path, buf.Bytes(), fresh); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}

// Values returns the effective settings as plain YAML values keyed by name.
func (c *Config) Values() (map[string]any, error) { return asMap(c) }

func asMap(cfg *Config) (map[string]any, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, yaml.Unmarshal(data, &m)
}

// normalize converts a Go value to the form produced by YAML decoding.
func normalize(v any) (any, error) {
	data, err := yaml.Marshal(map[string]any{"v": v})
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m["v"], nil
}

func setKey(mapping *yaml.Node, key string, value any) error {
	var node yaml.Node
	if err := node.Encode(value); err != nil {
		return err
	}
	if node.Kind == yaml.SequenceNode && len(node.Content) == 0 {
		node.Style = yaml.FlowStyle
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			old := mapping.Content[i+1]
			node.LineComment = old.LineComment
			node.HeadComment = old.HeadComment
			node.FootComment = old.FootComment
			mapping.Content[i+1] = &node
			return nil
		}
	}
	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &node)
	return nil
}

// writeAtomic never exposes a partially written configuration. New files are
// private (0600); existing files keep their permissions.
func writeAtomic(path string, data []byte, fresh bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	mode := os.FileMode(0600)
	if !fresh {
		if info, err := os.Stat(path); err == nil {
			mode = info.Mode().Perm()
		}
	}
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
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

// TemplateConfig returns the settings of a new installation.
func TemplateConfig() *Config {
	cfg, err := parse(Template, "template")
	if err != nil {
		panic("embedded configuration template is invalid: " + err.Error())
	}
	return cfg
}

// LegacyConfigPath is the default configuration path of Mesh Watchdog.
func LegacyConfigPath() string {
	_, path := legacyDefaults()
	return path
}
