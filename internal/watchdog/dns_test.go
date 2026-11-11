package watchdog

import (
	"context"
	"errors"
	"testing"

	"github.com/repentandliveholy/netriser/internal/canary"
	"github.com/repentandliveholy/netriser/internal/netengine"
)

type dnsMockEngine struct {
	*mockEngine
	captures, repairs int
	repair            func()
	err               error
}

func (e *dnsMockEngine) CaptureDNSBaseline(context.Context) error { e.captures++; return nil }
func (e *dnsMockEngine) RestoreDNS(context.Context) ([]netengine.ActionResult, error) {
	e.repairs++
	if e.repair != nil {
		e.repair()
	}
	status := netengine.ActionExecuted
	if e.err != nil {
		status = netengine.ActionFailed
	}
	return []netengine.ActionResult{{Type: netengine.ActionRestoreDNS, Status: status}}, e.err
}
func dnsFailed() canary.HealthResult {
	return canary.HealthResult{InternetHealthy: true, DNS: &canary.DNSResult{Healthy: false}}
}
func dnsHealthy() canary.HealthResult {
	return canary.HealthResult{Healthy: true, InternetHealthy: true, DNS: &canary.DNSResult{Healthy: true}}
}

func TestDNSOnlyRecoveryDoesNotEscalateEvenWithRebootEnabled(t *testing.T) {
	w, cfg, base, checker := setupTestWatchdog(t)
	cfg.EnableReboot = true
	engine := &dnsMockEngine{mockEngine: base, err: errors.New("resolver still broken")}
	w.SetEngine(engine)
	checker.fastResult = dnsFailed()
	if err := w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, FailCount: 20}); err != nil {
		t.Fatal(err)
	}
	for range 7 {
		rep, err := w.RunCheckCycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if rep.Healthy || rep.FailCount != 0 || rep.RemediationStage != 0 {
			t.Fatalf("DNS entered network escalation: %+v", rep)
		}
	}
	if engine.repairs != 7 || base.rebootCalled || base.quarantineCalled || base.cleanCalled || base.restartCalled {
		t.Fatalf("unrelated network actions during DNS failure: %+v", base)
	}
}

func TestDNSRecoveryVerifiesResolution(t *testing.T) {
	w, _, base, checker := setupTestWatchdog(t)
	engine := &dnsMockEngine{mockEngine: base, repair: func() { checker.fastResult = dnsHealthy() }}
	w.SetEngine(engine)
	checker.fastResult = dnsFailed()
	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Healthy || !rep.Remediated || rep.InitialHealthy || rep.PostCanaryResult == nil || !rep.PostCanaryResult.DNS.Healthy {
		t.Fatalf("repair not verified: %+v", rep)
	}
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if engine.captures != 1 {
		t.Fatal("healthy resolver was not cached")
	}
}

func TestDNSRecoveryRespectsPermissions(t *testing.T) {
	for _, mode := range []string{"observation", "disabled", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			w, cfg, base, checker := setupTestWatchdog(t)
			cfg.EnableReboot = true
			engine := &dnsMockEngine{mockEngine: base}
			if mode != "unsupported" {
				w.SetEngine(engine)
			}
			cfg.ObservationMode = mode == "observation"
			cfg.AllowDNSRecovery = mode != "disabled"
			checker.fastResult = dnsFailed()
			rep, err := w.RunCheckCycle(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if rep.Healthy || rep.RemediationStage != 0 || engine.repairs != 0 || base.rebootCalled || base.quarantineCalled {
				t.Fatalf("DNS permissions ignored: %+v", rep)
			}
		})
	}
}

type dnsTransitionChecker struct{ calls int }

func (c *dnsTransitionChecker) CheckFast(context.Context) canary.HealthResult {
	c.calls++
	if c.calls == 1 {
		return canary.HealthResult{Healthy: false}
	}
	return dnsFailed()
}
func (c *dnsTransitionChecker) CheckDetailed(ctx context.Context) canary.HealthResult {
	return c.CheckFast(ctx)
}

func TestDNSFailureDuringPreRebootAbortsReboot(t *testing.T) {
	w, cfg, base, _ := setupTestWatchdog(t)
	cfg.EnableReboot = true
	cfg.FailThresholdStage1, cfg.FailThresholdStage2, cfg.FailThresholdStage3, cfg.FailThresholdStage4Reboot = 1, 1, 1, 1
	w.SetChecker(&dnsTransitionChecker{})
	w.SetEngine(&dnsMockEngine{mockEngine: base})
	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if base.rebootCalled || rep.RemediationStage != 0 || rep.FailCount != 0 {
		t.Fatalf("DNS-only pre-reboot result rebooted: %+v", rep)
	}
	history, err := w.rebootTracker.LoadHistory()
	if err != nil || len(history) != 0 {
		t.Fatalf("reboot budget spent on DNS: %v %v", history, err)
	}
}

func TestDNSDryRunNeverPlansRebootAndDoesNotMutate(t *testing.T) {
	w, cfg, base, checker := setupTestWatchdog(t)
	cfg.EnableReboot = true
	engine := &dnsMockEngine{mockEngine: base}
	w.SetEngine(engine)
	checker.fastResult = dnsFailed()
	if err := w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, FailCount: 20}); err != nil {
		t.Fatal(err)
	}
	rep, err := w.EvaluateDryRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state, err := w.stateMgr.LoadStateReadOnly()
	if err != nil {
		t.Fatal(err)
	}
	if rep.EscalationStage != 0 || !rep.ActionAllowed || rep.ProjectedFailCount != 0 || state.FailCount != 20 || engine.repairs != 0 || engine.captures != 0 {
		t.Fatalf("unsafe or mutating DNS dry run: %+v", rep)
	}
}
