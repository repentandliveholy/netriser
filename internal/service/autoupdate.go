package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/updater"
)

// automaticDue defers updates during outages and startup. The scheduler runs
// independently so a slow distribution server never delays network recovery.
func automaticDue(cfg *config.Config, healthy bool, started, lastAttempt, now time.Time) bool {
	if !cfg.AutoUpdate || cfg.ObservationMode || !healthy || now.Sub(started) < 5*time.Minute {
		return false
	}
	return lastAttempt.IsZero() || now.Sub(lastAttempt) >= time.Duration(cfg.AutoUpdateIntervalSec)*time.Second
}

func runAutomaticUpdates(ctx context.Context, configPath string, healthy *atomic.Bool) {
	started := time.Now()
	var lastAttempt time.Time
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Reload on/off, URL and interval without requiring a service restart.
			cfg, err := config.Load(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Auto-update config: %v\n", err)
				continue
			}
			if !automaticDue(cfg, healthy.Load(), started, lastAttempt, now) {
				continue
			}
			lastAttempt = now
			executable, err := updater.CurrentExecutablePath()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Auto-update executable: %v\n", err)
				continue
			}
			// A separate helper can restart its parent service, including Windows SCM.
			// It uses the same checksum validation and update lock as manual updates.
			updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			args := []string{"update"}
			if configPath != "" {
				args = append(args, "--config", configPath)
			}
			cmd := exec.CommandContext(updateCtx, executable, args...)
			detachUpdateHelper(cmd)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			err = cmd.Run()
			cancel()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "Auto-update failed: %v\n", err)
			}
		}
	}
}
