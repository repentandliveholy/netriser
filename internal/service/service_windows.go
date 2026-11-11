//go:build windows

package service

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

const ServiceName = "netriser"
const ServiceDisplayName = "NetRiser"
const ServiceDescription = "Monitors network health, protects against mesh default route hijacking, and performs auto-remediation."

type WindowsServiceManager struct {
	cfg *config.Config
}

func NewManager(cfg *config.Config) Manager {
	return &WindowsServiceManager{cfg: cfg}
}

func (m *WindowsServiceManager) Install(binPath, confPath string) error {
	if !filepath.IsAbs(binPath) {
		binPath, _ = filepath.Abs(binPath)
	}
	if confPath != "" && !filepath.IsAbs(confPath) {
		confPath, _ = filepath.Abs(confPath)
	}

	mSCM, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer mSCM.Disconnect()

	if legacy, legacyErr := mSCM.OpenService("mesh-watchdog"); legacyErr == nil {
		state, queryErr := legacy.Query()
		legacy.Close()
		if queryErr != nil {
			return fmt.Errorf("query legacy service: %w", queryErr)
		}
		if state.State != svc.Stopped {
			return fmt.Errorf("stop the legacy mesh-watchdog service before installing NetRiser")
		}
	}

	s, err := mSCM.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ServiceName)
	}

	execArgs := []string{}
	if confPath != "" {
		execArgs = append(execArgs, "--config", confPath)
	}
	execArgs = append(execArgs, "run")

	s, err = mSCM.CreateService(ServiceName, binPath, mgr.Config{
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "", // LocalSystem
	}, execArgs...)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	// Start service; if start fails, roll back service creation
	if err := s.Start(); err != nil {
		_ = s.Delete()
		return fmt.Errorf("failed to start service: %w", err)
	}
	return nil
}

func (m *WindowsServiceManager) Uninstall() error {
	mSCM, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer mSCM.Disconnect()

	s, err := mSCM.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", ServiceName)
	}
	defer s.Close()

	// Stop service if running
	_, _ = s.Control(svc.Stop)
	time.Sleep(1 * time.Second)

	if err := s.Delete(); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	return nil
}

func (m *WindowsServiceManager) Start() error {
	mSCM, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer mSCM.Disconnect()

	s, err := mSCM.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("failed to start service %s: %w", ServiceName, err)
	}
	return nil
}

func (m *WindowsServiceManager) Stop() error {
	mSCM, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer mSCM.Disconnect()

	s, err := mSCM.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("failed to stop service %s: %w", ServiceName, err)
	}
	return nil
}

func (m *WindowsServiceManager) Restart() error {
	mSCM, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer mSCM.Disconnect()

	s, err := mSCM.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %w", ServiceName, err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	time.Sleep(1 * time.Second)
	if err := s.Start(); err != nil {
		return fmt.Errorf("failed to start service %s after stop: %w", ServiceName, err)
	}
	return nil
}

func (m *WindowsServiceManager) Status() (string, error) {
	mSCM, err := mgr.Connect()
	if err != nil {
		return "unknown", err
	}
	defer mSCM.Disconnect()

	s, err := mSCM.OpenService(ServiceName)
	if err != nil {
		return "not installed", nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "unknown", err
	}
	switch status.State {
	case svc.Running:
		return "active (running)", nil
	case svc.Stopped:
		return "inactive (stopped)", nil
	case svc.StartPending:
		return "start pending", nil
	case svc.StopPending:
		return "stop pending", nil
	default:
		return fmt.Sprintf("state %d", status.State), nil
	}
}

type winServiceHandler struct {
	w   *watchdog.Watchdog
	cfg *config.Config
}

func (h *winServiceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = RunDaemonLoop(ctx, h.w, h.cfg)
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			<-done
			return false, 0
		}
	}

	return false, 0
}

func (m *WindowsServiceManager) Run(ctx context.Context, w *watchdog.Watchdog) error {
	isService, err := svc.IsWindowsService()
	if err == nil && isService {
		return svc.Run(ServiceName, &winServiceHandler{w: w, cfg: m.cfg})
	}
	// Run as interactive console daemon
	return RunDaemonLoop(ctx, w, m.cfg)
}
