package watchdog

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFastRecoveryDoesNotAccelerateReboot(t *testing.T) {
	w, cfg, engine, _ := setupTestWatchdog(t)
	cfg.EnableReboot = true
	cfg.RebootMinOutageSec = 300
	clock := w.clock.(*fakeClock)
	start := clock.Now()
	if err := w.writeFailCount(1); err != nil {
		t.Fatal(err)
	}
	clock.currentTime = start.Add(45 * time.Second)
	if err := w.writeFailCount(cfg.FailThresholdStage4Reboot - 1); err != nil {
		t.Fatal(err)
	}
	report, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if engine.rebootCalled || !strings.Contains(report.StageReason, "reboot_min_outage_sec") {
		t.Fatalf("fast recovery allowed reboot: %+v", report)
	}
	clock.currentTime = start.Add(5 * time.Minute)
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !engine.rebootCalled {
		t.Fatal("measured outage did not allow enabled reboot")
	}
	if err := w.writeFailCount(0); err != nil {
		t.Fatal(err)
	}
	state, _ := w.stateMgr.LoadStateReadOnly()
	if !state.FirstFailedAt.IsZero() {
		t.Fatal("recovery retained outage start")
	}
}

func TestLegacyFailureCountCannotBypassMeasuredRebootWindow(t *testing.T) {
	w, cfg, _, _ := setupTestWatchdog(t)
	cfg.RebootMinOutageSec = 300
	state := &WatchdogState{FailCount: 100}
	if allowed, _ := w.guardRebootOutage(state, true, ""); allowed {
		t.Fatal("legacy failure count bypassed time guard")
	}
	state.FirstFailedAt = w.clock.Now().Add(-10 * time.Minute)
	if allowed, _ := w.guardRebootOutage(state, false, "budget exhausted"); allowed {
		t.Fatal("time guard bypassed reboot budget")
	}
}
