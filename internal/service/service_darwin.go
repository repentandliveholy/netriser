//go:build darwin

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

const LaunchDaemonPlist = "/Library/LaunchDaemons/com.netriser.daemon.plist"

type DarwinServiceManager struct {
	cfg *config.Config
}

func NewManager(cfg *config.Config) Manager {
	return &DarwinServiceManager{cfg: cfg}
}

func (m *DarwinServiceManager) Install(binPath, confPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("service installation requires root privileges (uid 0)")
	}
	if _, err := exec.LookPath("launchctl"); err != nil {
		return fmt.Errorf("launchctl not found in PATH")
	}

	if exec.Command("launchctl", "list", "com.mesh.watchdog").Run() == nil {
		return fmt.Errorf("unload the legacy com.mesh.watchdog daemon before installing NetRiser")
	}

	if binPath == "" {
		binPath = "/usr/local/bin/netriser"
	}
	if !filepath.IsAbs(binPath) {
		binPath, _ = filepath.Abs(binPath)
	}
	if confPath != "" && !filepath.IsAbs(confPath) {
		confPath, _ = filepath.Abs(confPath)
	}

	plistContent := GenerateLaunchdPlist(binPath, confPath, m.cfg.LogFile)

	dir := filepath.Dir(LaunchDaemonPlist)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for launchd plist: %w", err)
	}

	if err := os.WriteFile(LaunchDaemonPlist, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write launchd plist: %w", err)
	}

	_ = exec.Command("launchctl", "unload", "-w", LaunchDaemonPlist).Run()
	if out, err := exec.Command("launchctl", "load", "-w", LaunchDaemonPlist).CombinedOutput(); err != nil {
		_ = os.Remove(LaunchDaemonPlist)
		return fmt.Errorf("failed to load launchd daemon: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	return nil
}

func (m *DarwinServiceManager) Uninstall() error {
	_ = exec.Command("launchctl", "unload", "-w", LaunchDaemonPlist).Run()
	if err := os.Remove(LaunchDaemonPlist); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove launchd plist: %w", err)
	}
	return nil
}

func (m *DarwinServiceManager) Start() error {
	if out, err := exec.Command("launchctl", "load", "-w", LaunchDaemonPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start launchd daemon: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *DarwinServiceManager) Stop() error {
	if out, err := exec.Command("launchctl", "unload", "-w", LaunchDaemonPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop launchd daemon: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *DarwinServiceManager) Restart() error {
	_ = exec.Command("launchctl", "unload", "-w", LaunchDaemonPlist).Run()
	if out, err := exec.Command("launchctl", "load", "-w", LaunchDaemonPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to reload launchd daemon: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *DarwinServiceManager) Status() (string, error) {
	out, err := exec.Command("launchctl", "list", "com.netriser.daemon").CombinedOutput()
	if err != nil {
		return "inactive", nil
	}
	if strings.Contains(string(out), `"PID"`) {
		return "active (running)", nil
	}
	return "loaded", nil
}

func (m *DarwinServiceManager) Run(ctx context.Context, w *watchdog.Watchdog) error {
	return RunDaemonLoop(ctx, w, m.cfg)
}
