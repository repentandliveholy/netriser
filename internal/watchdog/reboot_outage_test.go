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

// One reboot per outage: after it, stages 1-3 run again from the start; if
// access still does not return, NetRiser pauses (no reboot, no actions) until
// connectivity returns, then everything is available again.
func TestOneRebootPerOutageThenPause(t *testing.T) {
	w, cfg, engine, checker := setupTestWatchdog(t)
	cfg.EnableReboot = true
	cfg.RebootMinOutageSec = 60
	cfg.RebootBudgetWindowSec = 1 // the per-outage rule must hold without the budget
	clock := w.clock.(*fakeClock)
	start := clock.Now()
	if err := w.writeFailCount(1); err != nil {
		t.Fatal(err)
	}
	clock.currentTime = start.Add(10 * time.Minute)
	w.writeFailCount(cfg.FailThresholdStage4Reboot - 1)
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !engine.rebootCalled {
		t.Fatal("first reboot did not happen")
	}
	state, _ := w.stateMgr.LoadStateReadOnly()
	if state.FailCount != 0 || !state.RebootedInOutage {
		t.Fatalf("reboot not recorded for a fresh round of stages: %+v", state)
	}

	// After the restart: stages 1, 2, 3 run again.
	engine.rebootCalled = false
	var stages []int
	for i := 0; i < cfg.FailThresholdStage4Reboot-1; i++ {
		clock.currentTime = clock.currentTime.Add(time.Minute)
		rep, err := w.RunCheckCycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		stages = append(stages, rep.RemediationStage)
	}
	if stages[0] != 1 || stages[len(stages)-1] != 3 {
		t.Fatalf("stages after reboot: %v", stages)
	}

	// Still no access: pause, with no second reboot and no further actions.
	engine.cleanCalled, engine.restartCalled = false, false
	for i := 0; i < 3; i++ {
		clock.currentTime = clock.currentTime.Add(time.Hour)
		rep, err := w.RunCheckCycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rep.StageReason, "paused") {
			t.Fatalf("not paused: %+v", rep)
		}
	}
	if engine.rebootCalled || engine.cleanCalled || engine.restartCalled {
		t.Fatalf("acted while paused: reboot=%v clean=%v restart=%v", engine.rebootCalled, engine.cleanCalled, engine.restartCalled)
	}
	if out := w.Status(context.Background()); !strings.Contains(out, "Recovery Paused:") {
		t.Fatalf("status does not show the pause:\n%s", out)
	}

	// Connectivity returns: the pause and the reboot mark are cleared.
	checker.fastResult.Healthy = true
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ = w.stateMgr.LoadStateReadOnly()
	if state.RebootedInOutage || state.RecoveryPaused || state.FailCount != 0 {
		t.Fatalf("recovery did not reset the outage: %+v", state)
	}
}
