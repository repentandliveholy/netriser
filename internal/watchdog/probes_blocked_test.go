package watchdog

import (
	"context"
	"strings"
	"testing"
	"time"
)

// blockedChecker fails every internet probe while system DNS and the router
// answer, as on a network that filters the probe addresses.
type blockedChecker struct {
	fakeChecker
	blocked  bool
	gateways []string
}

func (b *blockedChecker) ProbesBlocked(ctx context.Context, gateway string) (bool, string) {
	b.gateways = append(b.gateways, gateway)
	if !b.blocked {
		return false, ""
	}
	return true, "system DNS resolves example.com and the router " + gateway + " answers"
}

// Stages 1-2 still run (they remove a VPN that hijacked the route); network
// restart and reboot are held back while the probes look blocked.
func TestBlockedProbesHoldBackStrongActions(t *testing.T) {
	w, cfg, engine, _ := setupTestWatchdog(t)
	cfg.EnableReboot = true
	checker := &blockedChecker{blocked: true}
	w.SetChecker(checker)
	clock := w.clock.(*fakeClock)

	var stages []int
	for i := 0; i < cfg.FailThresholdStage4Reboot+2; i++ {
		clock.currentTime = clock.currentTime.Add(time.Hour)
		rep, err := w.RunCheckCycle(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		stages = append(stages, rep.RemediationStage)
		if rep.RemediationStage >= 3 && !strings.Contains(rep.StageReason, "blocked") {
			t.Fatalf("stage %d not held back: %+v", rep.RemediationStage, rep)
		}
	}
	if stages[0] != 1 || !engine.cleanCalled {
		t.Fatalf("stage 1 did not run: %v", stages)
	}
	if engine.restartCalled || engine.rebootCalled {
		t.Fatalf("strong action while probes look blocked: restart=%v reboot=%v (stages %v)", engine.restartCalled, engine.rebootCalled, stages)
	}
	if len(checker.gateways) == 0 || checker.gateways[0] != "192.168.1.1" {
		t.Fatalf("gateway not passed: %v", checker.gateways)
	}
	if out := w.Status(context.Background()); !strings.Contains(out, "Internet Probes:") {
		t.Fatalf("status does not show blocked probes:\n%s", out)
	}
	if dry, _ := w.EvaluateDryRun(context.Background()); dry == nil || dry.ActionAllowed || !strings.Contains(dry.Reason, "blocked") {
		t.Fatalf("dry run ignores blocked probes: %+v", dry)
	}

	// Connectivity returns: the mark is cleared.
	checker.fastResult.Healthy = true
	checker.fastResult.InternetHealthy = true
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, _ := w.stateMgr.LoadStateReadOnly(); state.ProbesBlocked {
		t.Fatal("blocked-probes mark survived recovery")
	}
}

// Without that evidence (DNS fails or the router is silent) escalation is
// unchanged and reaches the network restart.
func TestUnblockedOutageStillEscalates(t *testing.T) {
	w, cfg, engine, _ := setupTestWatchdog(t)
	w.SetChecker(&blockedChecker{blocked: false})
	clock := w.clock.(*fakeClock)
	for i := 0; i < cfg.FailThresholdStage3; i++ {
		clock.currentTime = clock.currentTime.Add(time.Minute)
		if _, err := w.RunCheckCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !engine.restartCalled {
		t.Fatal("network restart did not run without blocked-probe evidence")
	}
}
