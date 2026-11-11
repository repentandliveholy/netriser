//go:build !linux && !windows && !darwin

package service

import (
	"context"
	"fmt"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

type StubManager struct {
	cfg *config.Config
}

func NewManager(cfg *config.Config) Manager {
	return &StubManager{cfg: cfg}
}

func (m *StubManager) Install(binPath, confPath string) error {
	return fmt.Errorf("service installation not supported on this platform")
}

func (m *StubManager) Uninstall() error {
	return fmt.Errorf("service uninstallation not supported on this platform")
}

func (m *StubManager) Start() error {
	return fmt.Errorf("service start not supported on this platform")
}

func (m *StubManager) Stop() error {
	return fmt.Errorf("service stop not supported on this platform")
}

func (m *StubManager) Restart() error {
	return fmt.Errorf("service restart not supported on this platform")
}

func (m *StubManager) Status() (string, error) {
	return "unsupported", nil
}

func (m *StubManager) Run(ctx context.Context, w *watchdog.Watchdog) error {
	return RunDaemonLoop(ctx, w, m.cfg)
}
