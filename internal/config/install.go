package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Initialize creates a complete configuration on a fresh installation. Existing
// files, comments, paths and settings are preserved unless explicitly selected.
func Initialize(path string, autoUpdate, reboot, observation *bool) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		if autoUpdate != nil {
			cfg.AutoUpdate = *autoUpdate
		}
		if reboot != nil {
			cfg.EnableReboot = *reboot
		}
		if observation != nil {
			cfg.ObservationMode = *observation
		}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(path)
			return nil, fmt.Errorf("write configuration: %v; close: %v", writeErr, closeErr)
		}
		return cfg, nil
	} else if err != nil {
		return nil, err
	}
	if _, err := Load(path); err != nil {
		return nil, err
	}
	if autoUpdate != nil {
		if err := SetAutoUpdateEnabled(path, *autoUpdate); err != nil {
			return nil, err
		}
	}
	if reboot != nil {
		if err := SetRebootEnabled(path, *reboot); err != nil {
			return nil, err
		}
	}
	if observation != nil {
		if err := SetObservationMode(path, *observation); err != nil {
			return nil, err
		}
	}
	return Load(path)
}
