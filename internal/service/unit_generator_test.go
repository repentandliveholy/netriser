package service

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestEscapeSystemdArg(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple path",
			input:    "/usr/local/bin/mesh-watchdog",
			expected: "/usr/local/bin/mesh-watchdog",
		},
		{
			name:     "path with spaces",
			input:    "/opt/My Tools/bin/mesh-watchdog",
			expected: `"/opt/My Tools/bin/mesh-watchdog"`,
		},
		{
			name:     "path with quotes and backslashes",
			input:    `/opt/weird"dir\app`,
			expected: `"/opt/weird\"dir\\app"`,
		},
		{
			name:     "path with tabs",
			input:    "/opt/foo\tbar",
			expected: "\"/opt/foo\tbar\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EscapeSystemdArg(tc.input)
			if got != tc.expected {
				t.Errorf("EscapeSystemdArg(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestGenerateSystemdMainUnit(t *testing.T) {
	t.Run("without config", func(t *testing.T) {
		unit := GenerateSystemdMainUnit("/usr/local/bin/mesh-watchdog", "")
		if !strings.Contains(unit, "ExecStart=/usr/local/bin/mesh-watchdog run") {
			t.Errorf("expected ExecStart without config, got:\n%s", unit)
		}
		if !strings.Contains(unit, "After=network-online.target netriser-policy.service") {
			t.Errorf("expected dependency on network-online and policy service, got:\n%s", unit)
		}
	})

	t.Run("with config and spaces", func(t *testing.T) {
		unit := GenerateSystemdMainUnit("/opt/My Tools/mesh-watchdog", "/etc/Custom Configs/config.yaml")
		expectedExec := `ExecStart="/opt/My Tools/mesh-watchdog" --config "/etc/Custom Configs/config.yaml" run`
		if !strings.Contains(unit, expectedExec) {
			t.Errorf("expected ExecStart %q, got:\n%s", expectedExec, unit)
		}
	})
}

func TestGenerateSystemdPolicyUnit(t *testing.T) {
	t.Run("dependency ordering and oneshot", func(t *testing.T) {
		unit := GenerateSystemdPolicyUnit("/usr/bin/mesh-watchdog", "/etc/mesh-watchdog.yaml")
		expectedStart := `ExecStart=/usr/bin/mesh-watchdog --config /etc/mesh-watchdog.yaml apply-policy`
		expectedStop := `ExecStop=/usr/bin/mesh-watchdog --config /etc/mesh-watchdog.yaml remove-policy`
		if !strings.Contains(unit, expectedStart) {
			t.Errorf("expected ExecStart %q, got:\n%s", expectedStart, unit)
		}
		if !strings.Contains(unit, expectedStop) {
			t.Errorf("expected ExecStop %q, got:\n%s", expectedStop, unit)
		}
		if !strings.Contains(unit, "Before=netbird.service tailscaled.service zerotier-one.service nebula.service") {
			t.Errorf("expected Before= overlay services, got:\n%s", unit)
		}
		if !strings.Contains(unit, "Type=oneshot") || !strings.Contains(unit, "RemainAfterExit=yes") {
			t.Errorf("expected Type=oneshot and RemainAfterExit=yes, got:\n%s", unit)
		}
	})
}

func TestGenerateLaunchdPlist(t *testing.T) {
	t.Run("valid XML and escaping", func(t *testing.T) {
		binPath := "/opt/tools/mesh & watchdog <v1>"
		confPath := "/etc/configs/mesh & test.yaml"
		logFile := "/var/log/mesh & test.log"

		plist := GenerateLaunchdPlist(binPath, confPath, logFile)

		// Verify it is well-formed XML
		var parsed struct {
			XMLName xml.Name `xml:"plist"`
		}
		if err := xml.Unmarshal([]byte(plist), &parsed); err != nil {
			t.Fatalf("generated plist is not valid XML: %v\nContent:\n%s", err, plist)
		}

		if !strings.Contains(plist, "<string>/opt/tools/mesh &amp; watchdog &lt;v1&gt;</string>") {
			t.Errorf("binPath not properly escaped in plist: %s", plist)
		}
		if !strings.Contains(plist, "<string>--config</string>") {
			t.Errorf("--config missing from plist: %s", plist)
		}
		if !strings.Contains(plist, "<string>/etc/configs/mesh &amp; test.yaml</string>") {
			t.Errorf("confPath not properly escaped in plist: %s", plist)
		}
		if !strings.Contains(plist, "<string>run</string>") {
			t.Errorf("run command missing from plist: %s", plist)
		}
	})
}
