package netengine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

// SimulationSession manages an active rogue route injection and its rollback mechanism.
type SimulationSession interface {
	// Rollback immediately removes injected test routes and re-asserts physical baseline.
	Rollback(ctx context.Context) error
	// Disarm cancels the independent safety rollback timer once test routes are confirmed cleared.
	Disarm() error
}

type DetachedSimulationSession struct {
	stateDir     string
	scriptPath   string
	pidFile      string
	dummyGW      string
	baseline     Baseline
	runner       CommandRunner
	disarmed     bool
	rollbackProc *os.Process
}

func (s *DetachedSimulationSession) Disarm() error {
	if s.disarmed {
		return nil
	}
	s.disarmed = true

	// Terminate background detached process if still running
	if s.rollbackProc != nil {
		_ = s.rollbackProc.Kill()
	} else if data, err := os.ReadFile(s.pidFile); err == nil {
		if pid, pErr := strconv.Atoi(strings.TrimSpace(string(data))); pErr == nil && pid > 0 {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
	}

	_ = os.Remove(s.scriptPath)
	_ = os.Remove(s.pidFile)
	return nil
}

func (s *DetachedSimulationSession) Rollback(ctx context.Context) error {
	defer s.Disarm()

	// Platform-specific route removal
	switch runtime.GOOS {
	case "darwin":
		_, _ = s.runner.Run(ctx, "route", "-n", "delete", "default", s.dummyGW)
		if s.baseline.Gateway != "" && s.baseline.Interface != "" {
			_, _ = s.runner.Run(ctx, "route", "-n", "add", "default", s.baseline.Gateway, "-iface", s.baseline.Interface)
		}
	case "windows":
		_, _ = s.runner.Run(ctx, "route.exe", "delete", "0.0.0.0", "MASK", "0.0.0.0", s.dummyGW)
		if s.baseline.Gateway != "" {
			_, _ = s.runner.Run(ctx, "route.exe", "add", "0.0.0.0", "MASK", "0.0.0.0", s.baseline.Gateway, "METRIC", "10")
		}
	default: // linux
		_, _ = s.runner.Run(ctx, "ip", "route", "del", "default", "via", s.dummyGW)
		if s.baseline.Gateway != "" && s.baseline.Interface != "" {
			_, _ = s.runner.Run(ctx, "ip", "route", "replace", "default", "via", s.baseline.Gateway, "dev", s.baseline.Interface)
		}
	}

	return nil
}

// StartDetachedSimulation prepares safety scripts, spawns an independent detached timer process,
// and injects a rogue test route.
func StartDetachedSimulation(ctx context.Context, cfg *config.Config, runner CommandRunner, b Baseline, duration time.Duration) (SimulationSession, error) {
	if !b.IsValid() {
		return nil, fmt.Errorf("cannot simulate hijack: baseline is invalid (%+v)", b)
	}

	dummyGW := "198.51.100.254"
	_ = os.MkdirAll(cfg.StateDir, 0750)
	scriptPath := filepath.Join(cfg.StateDir, "safety_rollback.sh")
	pidFile := filepath.Join(cfg.StateDir, "safety_rollback.pid")

	seconds := int(duration.Seconds())
	if seconds <= 0 {
		seconds = 45
	}

	var scriptContent string
	var spawnCmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		scriptPath = filepath.Join(cfg.StateDir, "safety_rollback.cmd")
		scriptContent = fmt.Sprintf(`@echo off
timeout /t %d /nobreak >nul
route.exe delete 0.0.0.0 MASK 0.0.0.0 %s
if not "%s"=="" (
    route.exe add 0.0.0.0 MASK 0.0.0.0 %s METRIC 10
)
del "%%~f0" >nul 2>&1
del "%s" >nul 2>&1
`, seconds, dummyGW, b.Gateway, b.Gateway, pidFile)
		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0700); err != nil {
			return nil, fmt.Errorf("failed to create Windows rollback script: %w", err)
		}
		spawnCmd = exec.Command("cmd.exe", "/c", scriptPath)

	case "darwin":
		scriptContent = fmt.Sprintf(`#!/bin/sh
sleep %d
/sbin/route -n delete default %s >/dev/null 2>&1
if [ -n "%s" ] && [ -n "%s" ]; then
    /sbin/route -n add default %s -iface %s >/dev/null 2>&1
fi
rm -f "%s" "%s"
`, seconds, dummyGW, b.Gateway, b.Interface, b.Gateway, b.Interface, scriptPath, pidFile)
		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
			return nil, fmt.Errorf("failed to create macOS rollback script: %w", err)
		}
		spawnCmd = exec.Command("/bin/sh", scriptPath)

	default: // linux
		scriptContent = fmt.Sprintf(`#!/bin/sh
sleep %d
ip route del default via %s >/dev/null 2>&1
if [ -n "%s" ] && [ -n "%s" ]; then
    ip route replace default via %s dev %s >/dev/null 2>&1
fi
rm -f "%s" "%s"
`, seconds, dummyGW, b.Gateway, b.Interface, b.Gateway, b.Interface, scriptPath, pidFile)
		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
			return nil, fmt.Errorf("failed to create Linux rollback script: %w", err)
		}
		spawnCmd = exec.Command("/bin/sh", scriptPath)
	}

	// Start independent detached process
	session := &DetachedSimulationSession{
		stateDir:   cfg.StateDir,
		scriptPath: scriptPath,
		pidFile:    pidFile,
		dummyGW:    dummyGW,
		baseline:   b,
		runner:     runner,
	}

	if err := spawnCmd.Start(); err != nil {
		_ = os.Remove(scriptPath)
		return nil, fmt.Errorf("failed to start independent safety rollback process: %w", err)
	}

	session.rollbackProc = spawnCmd.Process
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(spawnCmd.Process.Pid)), 0640)

	// Detach process monitoring so parent exit does not kill or wait for it
	go func() {
		_ = spawnCmd.Wait()
	}()

	// Inject the rogue default route via runner
	var injectErr error
	switch runtime.GOOS {
	case "windows":
		_, injectErr = runner.Run(ctx, "route.exe", "add", "0.0.0.0", "MASK", "0.0.0.0", dummyGW, "METRIC", "1")
	case "darwin":
		_, injectErr = runner.Run(ctx, "route", "-n", "add", "default", dummyGW)
	default: // linux
		_, injectErr = runner.Run(ctx, "ip", "route", "replace", "default", "via", dummyGW, "dev", b.Interface, "onlink")
	}

	if injectErr != nil {
		_ = session.Rollback(ctx)
		return nil, fmt.Errorf("failed to inject rogue route: %w", injectErr)
	}

	return session, nil
}
