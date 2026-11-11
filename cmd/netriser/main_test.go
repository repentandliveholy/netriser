package main

import (
	"reflect"
	"testing"
)

func TestParseCLIArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected cliOptions
	}{
		{
			name: "default command",
			args: []string{},
			expected: cliOptions{
				commands: nil,
			},
		},
		{
			name: "command before flag",
			args: []string{"status", "--json"},
			expected: cliOptions{
				jsonOutput: true,
				commands:   []string{"status"},
			},
		},
		{
			name: "flag before command",
			args: []string{"--json", "status"},
			expected: cliOptions{
				jsonOutput: true,
				commands:   []string{"status"},
			},
		},
		{
			name: "config with space and dry-run",
			args: []string{"check", "--config", "/etc/mesh.yaml", "--dry-run", "-v"},
			expected: cliOptions{
				confPath:   "/etc/mesh.yaml",
				dryRun:     true,
				verbose:    true,
				commands:   []string{"check"},
			},
		},
		{
			name: "config with equals",
			args: []string{"--config=/opt/config.yaml", "service", "install"},
			expected: cliOptions{
				confPath: "/opt/config.yaml",
				commands: []string{"service", "install"},
			},
		},
		{
			name: "version and help flags",
			args: []string{"-V", "-h"},
			expected: cliOptions{
				version:  true,
				help:     true,
				commands: nil,
			},
		},
		{
			name: "update flags check and custom url",
			args: []string{"update", "--check", "--update-url", "https://custom.repo.org"},
			expected: cliOptions{
				commands:  []string{"update"},
				checkOnly: true,
				updateURL: "https://custom.repo.org",
			},
		},
		{
			name: "update with force flag",
			args: []string{"update", "--force"},
			expected: cliOptions{
				commands: []string{"update"},
				force:    true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCLIArgs(tc.args)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("parseCLIArgs(%v) = %+v, want %+v", tc.args, got, tc.expected)
			}
		})
	}
}
