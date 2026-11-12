package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write everywhere")
	}
	dir := t.TempDir()
	if err := configWritable(filepath.Join(dir, "new", "config.yaml")); err != nil {
		t.Fatalf("new file in a writable directory: %v", err)
	}
	existing := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(existing, []byte("a: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := configWritable(existing); err != nil {
		t.Fatalf("writable file: %v", err)
	}
	if err := os.Chmod(existing, 0400); err != nil {
		t.Fatal(err)
	}
	if configWritable(existing) == nil {
		t.Fatal("read-only file reported writable")
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0700) })
	if configWritable(filepath.Join(locked, "config.yaml")) == nil {
		t.Fatal("new file in a read-only directory reported writable")
	}
	if data, _ := os.ReadFile(existing); string(data) != "a: 1\n" {
		t.Fatal("check changed the file")
	}
}
