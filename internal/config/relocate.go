package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// relocatedKeys are the settings that hold files of a former Mesh Watchdog
// installation. state_dir comes before lock_file: on Windows the old lock
// file lives inside the old state directory and moves with it.
var relocatedKeys = []string{"state_dir", "log_file", "incident_dir", "lock_file"}

// RelocateLegacyPaths moves the state, log and incident files of a former
// Mesh Watchdog installation to the NetRiser locations and points the
// configuration at them. Only settings that still hold the old default path
// change; a path the user chose stays as it is. A setting is switched only
// after its data has moved: when the new location already holds data or the
// move fails, that setting keeps the old path and nothing is lost. It must run
// while the daemon is stopped or before the daemon opens its files. It returns
// one "key: old -> new" line per switched setting.
func RelocateLegacyPaths(configPath string) ([]string, error) {
	if configPath == "" {
		configPath = DefaultConfigPath()
	}
	legacy, _ := legacyDefaults()
	d := DefaultConfig()
	current := map[string]string{
		"state_dir":    d.StateDir,
		"log_file":     d.LogFile,
		"incident_dir": d.IncidentDir,
		"lock_file":    d.LockFile,
	}
	return relocateLegacyPaths(configPath, legacy, current)
}

func relocateLegacyPaths(configPath string, legacy, current map[string]string) ([]string, error) {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	root := doc.Content[0]
	values := map[string]*yaml.Node{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		values[root.Content[i].Value] = root.Content[i+1]
	}

	var moved []string
	var stateFrom, stateTo string
	for _, key := range relocatedKeys {
		node := values[key]
		if node == nil || node.Kind != yaml.ScalarNode || !samePath(node.Value, legacy[key]) {
			continue
		}
		from, to := node.Value, current[key]
		if samePath(from, to) {
			continue
		}
		var ok bool
		switch key {
		case "log_file":
			ok = moveLogFile(from, to)
		case "lock_file":
			// A lock file holds no data. Drop the old one, also where it
			// travelled inside the moved state directory.
			_ = os.Remove(from)
			if stateFrom != "" {
				if rel, err := filepath.Rel(stateFrom, from); err == nil && !strings.HasPrefix(rel, "..") {
					_ = os.Remove(filepath.Join(stateTo, rel))
				}
			}
			ok = true
		default:
			ok = moveDir(from, to)
			if ok && key == "state_dir" {
				stateFrom, stateTo = from, to
			}
		}
		if !ok {
			continue
		}
		node.Value, node.Style, node.Tag = to, 0, "!!str"
		moved = append(moved, fmt.Sprintf("%s: %s -> %s", key, from, to))
	}
	if len(moved) == 0 {
		return nil, nil
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, err
	}
	if err := replaceFile(configPath, out); err != nil {
		return nil, err
	}
	removeEmptyLegacyDirs(legacy)
	return moved, nil
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// moveDir moves a directory to a new place. A missing source is nothing to
// move; a destination that already holds files is never overwritten.
func moveDir(from, to string) bool {
	if _, err := os.Stat(from); os.IsNotExist(err) {
		return true
	} else if err != nil {
		return false
	}
	if entries, err := os.ReadDir(to); err == nil {
		if len(entries) > 0 {
			return false
		}
		if os.Remove(to) != nil {
			return false
		}
	} else if !os.IsNotExist(err) {
		return false
	}
	if os.MkdirAll(filepath.Dir(to), 0755) != nil {
		return false
	}
	return os.Rename(from, to) == nil
}

// moveLogFile moves a log file and its rotated copy (".1"). An existing log
// at the destination is never overwritten.
func moveLogFile(from, to string) bool {
	if _, err := os.Stat(to); err == nil {
		return false
	} else if !os.IsNotExist(err) {
		return false
	}
	if os.MkdirAll(filepath.Dir(to), 0755) != nil {
		return false
	}
	if _, err := os.Stat(from); err == nil {
		if os.Rename(from, to) != nil {
			return false
		}
	} else if !os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(to + ".1"); os.IsNotExist(err) {
		_ = os.Rename(from+".1", to+".1")
	}
	return true
}

// replaceFile writes data next to path and renames it over path, keeping the
// file's permissions.
func replaceFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".netriser-relocate-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(info.Mode().Perm()); err == nil {
		_, err = f.Write(data)
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// removeEmptyLegacyDirs removes the now empty Mesh Watchdog directories. Only
// directories named after Mesh Watchdog (and their empty subdirectories) are
// touched, and os.Remove never deletes a directory that still has files.
func removeEmptyLegacyDirs(legacy map[string]string) {
	var dirs []string
	for _, key := range relocatedKeys {
		p := legacy[key]
		if p == "" {
			continue
		}
		for dir := filepath.Dir(p); strings.Contains(strings.ToLower(dir), "mesh-watchdog"); dir = filepath.Dir(dir) {
			dirs = append(dirs, dir)
			if filepath.Dir(dir) == dir {
				break
			}
		}
		if key == "state_dir" || key == "incident_dir" {
			dirs = append([]string{p}, dirs...)
		}
	}
	// Deepest first, so that parents are empty by the time they are tried.
	for pass := 0; pass < 3; pass++ {
		for _, dir := range dirs {
			_ = os.Remove(dir)
		}
	}
}
