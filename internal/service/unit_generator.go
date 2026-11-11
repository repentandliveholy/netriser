package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// EscapeSystemdArg quotes arguments containing whitespace, quotes, or backslashes according to systemd syntax.
func EscapeSystemdArg(s string) string {
	if strings.ContainsAny(s, " \t\n\"\\") {
		escaped := strings.ReplaceAll(s, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		return `"` + escaped + `"`
	}
	return s
}

// GenerateSystemdMainUnit generates systemd unit file content for the main watchdog daemon.
func GenerateSystemdMainUnit(binPath, confPath string) string {
	execStart := EscapeSystemdArg(binPath)
	if confPath != "" {
		execStart += " --config " + EscapeSystemdArg(confPath)
	}
	execStart += " run"

	return fmt.Sprintf(`[Unit]
Description=NetRiser & Auto-Remediation Daemon
After=network-online.target netriser-policy.service
Wants=network-online.target netriser-policy.service

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=10
KillMode=process

[Install]
WantedBy=multi-user.target
`, execStart)
}

// GenerateSystemdPolicyUnit generates systemd unit file content for the policy routing enforcer.
func GenerateSystemdPolicyUnit(binPath, confPath string) string {
	applyCmd := EscapeSystemdArg(binPath)
	removeCmd := EscapeSystemdArg(binPath)
	if confPath != "" {
		applyCmd += " --config " + EscapeSystemdArg(confPath)
		removeCmd += " --config " + EscapeSystemdArg(confPath)
	}
	applyCmd += " apply-policy"
	removeCmd += " remove-policy"

	return fmt.Sprintf(`[Unit]
Description=NetRiser Policy Routing Table Enforcer
After=network-online.target
Wants=network-online.target
Before=netbird.service tailscaled.service zerotier-one.service nebula.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s
ExecStop=%s

[Install]
WantedBy=multi-user.target
`, applyCmd, removeCmd)
}

// GenerateLaunchdPlist generates launchd plist XML content for macOS.
func GenerateLaunchdPlist(binPath, confPath, logFile string) string {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.netriser.daemon</string>
    <key>ProgramArguments</key>
    <array>
`)
	buf.WriteString(fmt.Sprintf("        <string>%s</string>\n", xmlEscape(binPath)))
	if confPath != "" {
		buf.WriteString("        <string>--config</string>\n")
		buf.WriteString(fmt.Sprintf("        <string>%s</string>\n", xmlEscape(confPath)))
	}
	buf.WriteString("        <string>run</string>\n")
	buf.WriteString(`    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
`)
	if logFile != "" {
		buf.WriteString(fmt.Sprintf("    <key>StandardOutPath</key>\n    <string>%s</string>\n", xmlEscape(logFile)))
		buf.WriteString(fmt.Sprintf("    <key>StandardErrorPath</key>\n    <string>%s</string>\n", xmlEscape(logFile)))
	}
	buf.WriteString(`</dict>
</plist>
`)
	return buf.String()
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
