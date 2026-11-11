package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

type Manager interface {
	Install(binPath, confPath string) error
	Uninstall() error
	Start() error
	Stop() error
	Restart() error
	Status() (string, error)
	Run(ctx context.Context, w *watchdog.Watchdog) error
}

// RunDaemonLoop runs regular daemon loop with ticker and OS signal handling.
func RunDaemonLoop(ctx context.Context, w *watchdog.Watchdog, cfg *config.Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var healthy atomic.Bool
	go runAutomaticUpdates(ctx, w.ConfigPath(), &healthy)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	// Run immediate initial check on startup with context
	report, err := w.RunCheckCycle(ctx)
	healthy.Store(err == nil && report != nil && report.Healthy)

	timer := time.NewTimer(nextCheckDelay(cfg, report, err))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig := <-sigChan:
			fmt.Printf("Received signal %v, terminating watchdog daemon...\n", sig)
			return nil
		case <-timer.C:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			report, err := w.RunCheckCycle(ctx)
			healthy.Store(err == nil && report != nil && report.Healthy)
			timer.Reset(nextCheckDelay(cfg, report, err))
		}
	}
}

// Schedule from completion: slow remediation never queues an immediate next
// stage, and healthy cycles resume the normal monitoring interval.
func nextCheckDelay(cfg *config.Config, report *watchdog.CheckReport, err error) time.Duration {
	if err == nil && report != nil && !report.Healthy && report.FailCount > 0 && cfg.RecoveryIntervalSec > 0 {
		return time.Duration(cfg.RecoveryIntervalSec) * time.Second
	}
	return cfg.CheckInterval()
}
