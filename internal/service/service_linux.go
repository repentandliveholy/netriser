//go:build linux

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

type LinuxServiceManager struct {
	cfg *config.Config
}

func NewManager(cfg *config.Config) Manager {
	return &LinuxServiceManager{cfg: cfg}
}

func (m *LinuxServiceManager) Install(binPath, confPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("service installation requires root privileges (uid 0)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found in PATH: systemd is required on Linux")
	}

	if out, _ := exec.Command("systemctl", "is-active", "mesh-watchdog.service").Output(); strings.TrimSpace(string(out)) == "active" || strings.TrimSpace(string(out)) == "activating" || strings.TrimSpace(string(out)) == "deactivating" || strings.TrimSpace(string(out)) == "reloading" {
		return fmt.Errorf("stop the legacy mesh-watchdog service before installing NetRiser")
	}

	if binPath == "" {
		binPath = "/usr/local/sbin/netriser"
	}
	if !filepath.IsAbs(binPath) {
		binPath, _ = filepath.Abs(binPath)
	}
	if confPath != "" && !filepath.IsAbs(confPath) {
		confPath, _ = filepath.Abs(confPath)
	}

	mainServiceUnit := GenerateSystemdMainUnit(binPath, confPath)
	policyServiceUnit := GenerateSystemdPolicyUnit(binPath, confPath)

	unitDir := "/etc/systemd/system"
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return fmt.Errorf("failed to create systemd unit directory: %w", err)
	}

	mainPath := filepath.Join(unitDir, "netriser.service")
	policyPath := filepath.Join(unitDir, "netriser-policy.service")

	rollback := func() {
		_ = exec.Command("systemctl", "stop", "netriser.service").Run()
		_ = exec.Command("systemctl", "disable", "netriser.service").Run()
		_ = exec.Command("systemctl", "stop", "netriser-policy.service").Run()
		_ = exec.Command("systemctl", "disable", "netriser-policy.service").Run()
		_ = os.Remove(mainPath)
		_ = os.Remove(policyPath)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}

	if err := os.WriteFile(mainPath, []byte(mainServiceUnit), 0644); err != nil {
		return fmt.Errorf("failed to write netriser.service: %w", err)
	}
	if err := os.WriteFile(policyPath, []byte(policyServiceUnit), 0644); err != nil {
		_ = os.Remove(mainPath)
		return fmt.Errorf("failed to write netriser-policy.service: %w", err)
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("systemctl daemon-reload failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "enable", "netriser-policy.service").CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("failed to enable netriser-policy.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "restart", "netriser-policy.service").CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("failed to start netriser-policy.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "enable", "netriser.service").CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("failed to enable netriser.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "restart", "netriser.service").CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("failed to start netriser.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	return nil
}

func (m *LinuxServiceManager) Uninstall() error {
	var errs []string
	if out, err := exec.Command("systemctl", "stop", "netriser.service").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Sprintf("failed to stop netriser: %v (%s)", err, strings.TrimSpace(string(out))))
	}
	_ = exec.Command("systemctl", "disable", "netriser.service").Run()
	_ = exec.Command("systemctl", "stop", "netriser-policy.service").Run()
	_ = exec.Command("systemctl", "disable", "netriser-policy.service").Run()

	_ = os.Remove("/etc/systemd/system/netriser.service")
	_ = os.Remove("/etc/systemd/system/netriser-policy.service")

	_ = exec.Command("systemctl", "daemon-reload").Run()
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (m *LinuxServiceManager) Start() error {
	if out, err := exec.Command("systemctl", "start", "netriser.service").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start netriser.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *LinuxServiceManager) Stop() error {
	if out, err := exec.Command("systemctl", "stop", "netriser.service").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop netriser.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *LinuxServiceManager) Restart() error {
	if out, err := exec.Command("systemctl", "restart", "netriser.service").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restart netriser.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *LinuxServiceManager) Status() (string, error) {
	out, err := exec.Command("systemctl", "is-active", "netriser.service").CombinedOutput()
	state := strings.TrimSpace(string(out))
	if err != nil && state == "" {
		return "inactive", err
	}
	return state, nil
}

func (m *LinuxServiceManager) Run(ctx context.Context, w *watchdog.Watchdog) error {
	return RunDaemonLoop(ctx, w, m.cfg)
}
