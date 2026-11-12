package watchdog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/canary"
	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
)

type mockEngine struct {
	cleanCalled      bool
	quarantineCalled bool
	restoreCalled    bool
	restartCalled    bool
	rebootCalled     bool
	rebootReason     string
	overrideBaseline bool
	baseline         netengine.Baseline
	baselineErr      error
	restartErr       error
	restoreErr       error
	restoredServices []string
	policyCalled     bool
	cleanActions     []netengine.ActionResult
	quarantineActs   []netengine.ActionResult
	restoreActs      []netengine.ActionResult
	rogue            []string
}

func (m *mockEngine) RogueDefaultRoutes(ctx context.Context) ([]string, error) {
	return m.rogue, nil
}

func (m *mockEngine) DetectBaseline(ctx context.Context) (netengine.Baseline, error) {
	if m.overrideBaseline {
		return m.baseline, m.baselineErr
	}
	return netengine.Baseline{
		Interface: "eth0",
		Gateway:   "192.168.1.1",
		IP:        "192.168.1.50",
	}, nil
}

func (m *mockEngine) ApplyPolicyRouting(ctx context.Context, b netengine.Baseline) error {
	m.policyCalled = true
	return nil
}

func (m *mockEngine) RemovePolicyRouting(ctx context.Context, b netengine.Baseline) error {
	return nil
}

func (m *mockEngine) SurgicalCleanRoutes(ctx context.Context, b netengine.Baseline) ([]netengine.ActionResult, error) {
	m.cleanCalled = true
	if len(m.cleanActions) > 0 {
		return m.cleanActions, nil
	}
	return []netengine.ActionResult{
		{
			Type:        netengine.ActionCleanRoute,
			Target:      "0.0.0.0/1 dev wt0",
			Status:      netengine.ActionExecuted,
			Description: "mock cleaned rogue route",
		},
	}, nil
}

func (m *mockEngine) QuarantineMeshServices(ctx context.Context) ([]netengine.ActionResult, error) {
	m.quarantineCalled = true
	if len(m.quarantineActs) > 0 {
		return m.quarantineActs, nil
	}
	return []netengine.ActionResult{
		{
			Type:        netengine.ActionQuarantineService,
			Target:      "netbird",
			Status:      netengine.ActionExecuted,
			Description: "mock quarantined netbird",
		},
	}, nil
}

func (m *mockEngine) RestoreMeshServices(ctx context.Context, services []string) ([]netengine.ActionResult, error) {
	m.restoreCalled = true
	m.restoredServices = append(m.restoredServices, services...)
	if m.restoreErr != nil {
		return nil, m.restoreErr
	}
	if len(m.restoreActs) > 0 {
		return m.restoreActs, nil
	}
	var res []netengine.ActionResult
	for _, s := range services {
		res = append(res, netengine.ActionResult{
			Type:        netengine.ActionRestoreService,
			Target:      s,
			Status:      netengine.ActionExecuted,
			Description: fmt.Sprintf("mock restored %s", s),
		})
	}
	return res, nil
}

func (m *mockEngine) RestartNetworkStack(ctx context.Context, b netengine.Baseline) error {
	m.restartCalled = true
	return m.restartErr
}

func (m *mockEngine) EmergencyReboot(ctx context.Context, reason string) error {
	m.rebootCalled = true
	m.rebootReason = reason
	return nil
}

func (m *mockEngine) SimulateHijack(ctx context.Context, b netengine.Baseline, duration time.Duration) (func(), error) {
	return func() {}, nil
}

func (m *mockEngine) SimulateHijackSession(ctx context.Context, b netengine.Baseline, duration time.Duration) (netengine.SimulationSession, error) {
	return &mockSimulationSession{}, nil
}

type mockSimulationSession struct {
	rolledBack bool
	disarmed   bool
}

func (s *mockSimulationSession) Rollback(ctx context.Context) error {
	s.rolledBack = true
	return nil
}

func (s *mockSimulationSession) Disarm() error {
	s.disarmed = true
	return nil
}

func (m *mockEngine) DumpDiagnostics(ctx context.Context, b netengine.Baseline) (string, error) {
	return "mock diagnostics", nil
}

type fakeChecker struct {
	fastResult     canary.HealthResult
	detailedResult canary.HealthResult
	delay          time.Duration
}

func (f *fakeChecker) CheckFast(ctx context.Context) canary.HealthResult {
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return canary.HealthResult{Healthy: false, CheckedAt: time.Now()}
		case <-time.After(f.delay):
		}
	}
	return f.fastResult
}

func (f *fakeChecker) CheckDetailed(ctx context.Context) canary.HealthResult {
	return f.detailedResult
}

type fakeClock struct {
	currentTime time.Time
	sleepErr    error
}

func (f *fakeClock) Now() time.Time {
	if f.currentTime.IsZero() {
		return time.Now()
	}
	return f.currentTime
}

func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if f.sleepErr != nil {
		return f.sleepErr
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func setupTestWatchdog(t *testing.T) (*Watchdog, *config.Config, *mockEngine, *fakeChecker) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ObservationMode = false // tests exercise active recovery
	cfg.StateDir = filepath.Join(tmpDir, "state")
	cfg.IncidentDir = filepath.Join(tmpDir, "incidents")
	cfg.LockFile = filepath.Join(tmpDir, "state", "test.lock")
	cfg.LogFile = filepath.Join(tmpDir, "test.log")
	cfg.CanaryTargets = []string{"1.1.1.1:53"}
	cfg.ProbeTimeoutSec = 1
	cfg.StartupGraceSec = 0    // disabled in basic tests unless tested explicitly
	cfg.RebootMinOutageSec = 0 // individual reboot tests control this explicitly

	mock := &mockEngine{}
	fChecker := &fakeChecker{
		fastResult: canary.HealthResult{
			Healthy: false,
		},
	}
	clock := &fakeClock{currentTime: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}

	w := NewWatchdogWithDeps(cfg, mock, fChecker, clock, NewLogger("", false))
	return w, cfg, mock, fChecker
}

func TestSimulationNeverReboots(t *testing.T) {
	w, cfg, _, _ := setupTestWatchdog(t)
	cfg.EnableReboot = true

	session, err := w.SimulateHijackSession(context.Background(), 45*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnableReboot {
		t.Fatal("SimulateHijackSession must force EnableReboot to false")
	}
	_ = session.Disarm()
}

func TestWatchdogCheckCycle(t *testing.T) {
	w, _, mock, _ := setupTestWatchdog(t)

	// First cycle -> Unhealthy -> Stage 1
	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Healthy {
		t.Fatal("expected unhealthy")
	}
	if rep.FailCount != 1 {
		t.Fatalf("expected fail count 1, got %d", rep.FailCount)
	}
	if !mock.cleanCalled {
		t.Fatal("expected SurgicalCleanRoutes to be called")
	}
	if len(rep.ActionsTaken) == 0 {
		t.Fatal("expected structured actions taken in report")
	}
	if rep.ActionsTaken[0].Status != netengine.ActionExecuted {
		t.Fatalf("expected action status executed, got %s", rep.ActionsTaken[0].Status)
	}

	// Reset
	w.Reset()
	if w.readFailCount() != 0 {
		t.Fatalf("expected fail count 0 after reset")
	}
}

func TestWatchdogContextCancellation(t *testing.T) {
	w, _, _, fChecker := setupTestWatchdog(t)
	fChecker.delay = 500 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	_, err := w.RunCheckCycle(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled error, got %v", err)
	}
}

func TestWatchdogStateWriteFailureAbortsEscalation(t *testing.T) {
	w, cfg, mock, _ := setupTestWatchdog(t)

	// Make state directory unwriteable
	cfg.StateDir = "/dev/null/impossible_dir"
	w.stateMgr = NewStateManager(cfg.StateDir)

	_, err := w.RunCheckCycle(context.Background())
	if err == nil {
		t.Fatal("expected error when state file cannot be written")
	}
	if mock.cleanCalled {
		t.Fatal("expected remediation to be aborted when state persistence fails")
	}
}

func TestStateManagerLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	sm := NewStateManager(tmpDir)

	// Save state
	state := &WatchdogState{
		Version:   1,
		FailCount: 3,
		Baseline: netengine.Baseline{
			Interface: "eth0",
			IP:        "192.168.1.50",
			Gateway:   "192.168.1.1",
		},
		QuarantinedServices: []ServiceQuarantineRecord{
			{
				Name:          "netbird",
				QuarantinedAt: time.Now(),
				Attempts:      1,
			},
		},
	}

	if err := sm.SaveState(state); err != nil {
		t.Fatalf("failed to save state: %v", err)
	}

	// Load state
	loaded, err := sm.LoadState()
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if loaded.FailCount != 3 || loaded.Baseline.Interface != "eth0" || len(loaded.QuarantinedServices) != 1 {
		t.Fatalf("loaded state mismatch: %+v", loaded)
	}
}

func TestLegacyStateMigration(t *testing.T) {
	tmpDir := t.TempDir()
	// Write legacy files
	_ = os.WriteFile(filepath.Join(tmpDir, "fail_count"), []byte("4\n"), 0640)
	_ = os.WriteFile(filepath.Join(tmpDir, "quarantined_services"), []byte("netbird tailscaled\n"), 0640)
	_ = os.WriteFile(filepath.Join(tmpDir, "baseline.json"), []byte(`{"interface":"eth0","ip":"192.168.1.50","gateway":"192.168.1.1"}`), 0640)

	sm := NewStateManager(tmpDir)
	migrated, err := sm.LoadState()
	if err != nil {
		t.Fatalf("migration error: %v", err)
	}

	if migrated.FailCount != 4 {
		t.Fatalf("expected fail count 4, got %d", migrated.FailCount)
	}
	if migrated.Baseline.Interface != "eth0" {
		t.Fatalf("expected baseline interface eth0, got %s", migrated.Baseline.Interface)
	}
	if len(migrated.QuarantinedServices) != 2 {
		t.Fatalf("expected 2 quarantined services, got %d", len(migrated.QuarantinedServices))
	}
}

func TestSequentialQuarantineRecovery(t *testing.T) {
	w, cfg, mock, fChecker := setupTestWatchdog(t)
	mock.cleanCalled = false

	// Inject 2 quarantined services in state ready for retry
	state, _ := w.stateMgr.LoadState()
	state.QuarantinedServices = []ServiceQuarantineRecord{
		{
			Name:           "netbird",
			NextRetryAfter: w.clock.Now().Add(-1 * time.Minute), // ready
		},
		{
			Name:           "tailscaled",
			NextRetryAfter: w.clock.Now().Add(-1 * time.Minute), // ready
		},
	}
	_ = w.stateMgr.SaveState(state)

	// Case: network is healthy during check, and stays healthy after netbird is restored
	fChecker.fastResult = canary.HealthResult{Healthy: true}
	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rep.Healthy {
		t.Fatal("expected report to be healthy")
	}

	// Verify that services were processed sequentially: netbird was restored first
	if !mock.restoreCalled {
		t.Fatal("expected restore to be called")
	}

	// Verify netbird is removed from state, remaining only tailscaled
	updatedState, _ := w.stateMgr.LoadState()
	if len(updatedState.QuarantinedServices) != 1 || updatedState.QuarantinedServices[0].Name != "tailscaled" {
		t.Fatalf("expected only tailscaled to remain quarantined, got %+v", updatedState.QuarantinedServices)
	}
	_ = cfg
}

func TestWatchdogBelowStage1Threshold(t *testing.T) {
	w, cfg, mock, _ := setupTestWatchdog(t)
	cfg.FailThresholdStage1 = 3 // Requires 3 failures before Stage 1 remediation

	// Cycle 1: failCount becomes 1 (below Stage 1 threshold of 3)
	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.RemediationStage != 0 {
		t.Fatalf("expected stage 0 (observation), got %d", rep.RemediationStage)
	}
	if mock.cleanCalled {
		t.Fatal("expected no route cleaning before Stage 1 threshold is reached")
	}
}

func TestWatchdogInvalidBaselineSkipsRouteMutationAndReboot(t *testing.T) {
	w, cfg, mock, _ := setupTestWatchdog(t)
	cfg.EnableReboot = true
	// Force invalid baseline (empty interface and IP)
	mock.overrideBaseline = true
	mock.baseline = netengine.Baseline{}

	// Reach stage 1
	w.writeFailCount(cfg.FailThresholdStage1 - 1)
	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.cleanCalled {
		t.Fatal("expected cleanRoutes to NOT be called with invalid baseline")
	}
	if len(rep.ActionsTaken) == 0 || rep.ActionsTaken[0].Status != netengine.ActionSkipped {
		t.Fatalf("expected skipped action status for invalid baseline, got %v", rep.ActionsTaken)
	}

	// Reach stage 4 (Reboot) with invalid baseline
	w.writeFailCount(cfg.FailThresholdStage4Reboot - 1)
	rep, err = w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.rebootCalled {
		t.Fatal("expected reboot to NOT be triggered with invalid baseline")
	}
}

func TestRebootBudgetTracker(t *testing.T) {
	tmpDir := t.TempDir()
	clock := &fakeClock{currentTime: time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)}
	tracker := NewRebootTracker(tmpDir, clock)

	// Initially can reboot
	can, reason := tracker.CanReboot(1, 1*time.Hour)
	if !can {
		t.Fatalf("expected can reboot, got reason: %s", reason)
	}

	// Record a reboot at 10:00
	if err := tracker.RecordReboot(); err != nil {
		t.Fatalf("failed to record reboot: %v", err)
	}

	// Now budget is 1 reboot in 1 hour -> second reboot within 1 hour must be rejected
	can, reason = tracker.CanReboot(1, 1*time.Hour)
	if can {
		t.Fatal("expected reboot to be disallowed after exhausting budget")
	}

	// Advance time past 1 hour (to 11:05)
	clock.currentTime = clock.currentTime.Add(65 * time.Minute)
	can, reason = tracker.CanReboot(1, 1*time.Hour)
	if !can {
		t.Fatalf("expected reboot to be allowed after budget window expired, got: %s", reason)
	}
}

func TestWatchdogStartupGracePreventsReboot(t *testing.T) {
	w, cfg, mock, _ := setupTestWatchdog(t)
	cfg.EnableReboot = true
	cfg.StartupGraceSec = 60
	w.SetStartedAt(w.clock.Now()) // Just started

	// Set failure count directly to Stage 4 (e.g. leftover from previous crash)
	w.writeFailCount(cfg.FailThresholdStage4Reboot - 1)

	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.rebootCalled {
		t.Fatal("reboot should NOT trigger while in startup grace period")
	}
	foundSkipped := false
	for _, act := range rep.ActionsTaken {
		if act.Type == netengine.ActionReboot && act.Status == netengine.ActionSkipped {
			foundSkipped = true
		}
	}
	if !foundSkipped {
		t.Fatal("expected skipped reboot action during startup grace")
	}
}

func TestWatchdogPreRebootVerificationRestoredAbortsReboot(t *testing.T) {
	w, cfg, mock, fChecker := setupTestWatchdog(t)
	cfg.EnableReboot = true
	cfg.StartupGraceSec = 0
	cfg.RebootGraceSec = 5
	w.writeFailCount(cfg.FailThresholdStage4Reboot - 1)

	// Initial probe fails (triggering Stage 4), but during pre-reboot grace window connection recovers!
	firstCheck := true
	origFastResult := fChecker.fastResult
	_ = origFastResult
	// Create dynamic checker
	dynChecker := &dynamicChecker{
		onCheckFast: func(ctx context.Context) canary.HealthResult {
			if firstCheck {
				firstCheck = false
				return canary.HealthResult{Healthy: false}
			}
			// Connection recovered!
			return canary.HealthResult{Healthy: true, SuccessfulTarget: "1.1.1.1:53"}
		},
	}
	w.SetChecker(dynChecker)

	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.rebootCalled {
		t.Fatal("reboot should have been aborted when pre-reboot verification succeeded")
	}
	if !rep.Healthy {
		t.Fatal("report should indicate healthy after recovery")
	}
	if w.readFailCount() != 0 {
		t.Fatalf("fail count should be reset to 0 after recovery, got %d", w.readFailCount())
	}
}

type dynamicChecker struct {
	onCheckFast func(ctx context.Context) canary.HealthResult
}

func (d *dynamicChecker) CheckFast(ctx context.Context) canary.HealthResult {
	if d.onCheckFast != nil {
		return d.onCheckFast(ctx)
	}
	return canary.HealthResult{Healthy: false}
}

func (d *dynamicChecker) CheckDetailed(ctx context.Context) canary.HealthResult {
	return canary.HealthResult{Healthy: false}
}

func TestDecideEscalationTable(t *testing.T) {
	validBaseline := netengine.Baseline{Interface: "eth0", IP: "192.168.1.50", Gateway: "192.168.1.1"}
	invalidBaseline := netengine.Baseline{}

	cfg := config.DefaultConfig()
	cfg.ObservationMode = false
	cfg.FailThresholdStage1 = 2
	cfg.FailThresholdStage2 = 4
	cfg.FailThresholdStage3 = 6
	cfg.FailThresholdStage4Reboot = 8
	cfg.EnableReboot = true

	tests := []struct {
		name               string
		failCount          int
		baseline           netengine.Baseline
		rebootAllowed      bool
		inStartupGrace     bool
		mutateCfg          func(c *config.Config)
		expectedStage      int
		expectedAllowed    bool
		expectedActionType netengine.ActionType
	}{
		{
			name:               "below stage 1 threshold",
			failCount:          1,
			baseline:           validBaseline,
			rebootAllowed:      true,
			expectedStage:      0,
			expectedAllowed:    false,
			expectedActionType: "",
		},
		{
			name:               "stage 1 executed",
			failCount:          2,
			baseline:           validBaseline,
			rebootAllowed:      true,
			expectedStage:      1,
			expectedAllowed:    true,
			expectedActionType: netengine.ActionCleanRoute,
		},
		{
			name:               "stage 1 invalid baseline",
			failCount:          2,
			baseline:           invalidBaseline,
			rebootAllowed:      true,
			expectedStage:      1,
			expectedAllowed:    false,
			expectedActionType: netengine.ActionCleanRoute,
		},
		{
			name:               "stage 2 executed",
			failCount:          4,
			baseline:           validBaseline,
			rebootAllowed:      true,
			expectedStage:      2,
			expectedAllowed:    true,
			expectedActionType: netengine.ActionQuarantineService,
		},
		{
			name:      "stage 2 permission denied",
			failCount: 4,
			baseline:  validBaseline,
			mutateCfg: func(c *config.Config) {
				c.AllowServiceQuarantine = false
			},
			expectedStage:      2,
			expectedAllowed:    false,
			expectedActionType: netengine.ActionQuarantineService,
		},
		{
			name:               "stage 3 executed",
			failCount:          6,
			baseline:           validBaseline,
			rebootAllowed:      true,
			expectedStage:      3,
			expectedAllowed:    true,
			expectedActionType: netengine.ActionRestartStack,
		},
		{
			name:               "stage 4 executed when reboot enabled and budget ok",
			failCount:          8,
			baseline:           validBaseline,
			rebootAllowed:      true,
			expectedStage:      4,
			expectedAllowed:    true,
			expectedActionType: netengine.ActionReboot,
		},
		{
			name:      "stage 4 skipped when reboot disabled",
			failCount: 8,
			baseline:  validBaseline,
			mutateCfg: func(c *config.Config) {
				c.EnableReboot = false
			},
			rebootAllowed:      true,
			expectedStage:      4,
			expectedAllowed:    false,
			expectedActionType: netengine.ActionReboot,
		},
		{
			name:               "stage 4 skipped when startup grace active",
			failCount:          8,
			baseline:           validBaseline,
			rebootAllowed:      true,
			inStartupGrace:     true,
			expectedStage:      4,
			expectedAllowed:    false,
			expectedActionType: netengine.ActionReboot,
		},
		{
			name:               "stage 4 skipped when budget exhausted",
			failCount:          8,
			baseline:           validBaseline,
			rebootAllowed:      false,
			expectedStage:      4,
			expectedAllowed:    false,
			expectedActionType: netengine.ActionReboot,
		},
		{
			name:      "observation mode overrides everything",
			failCount: 10,
			baseline:  validBaseline,
			mutateCfg: func(c *config.Config) {
				c.ObservationMode = true
			},
			expectedStage:      0,
			expectedAllowed:    false,
			expectedActionType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			localCfg := *cfg
			if tt.mutateCfg != nil {
				tt.mutateCfg(&localCfg)
			}
			dec := DecideEscalation(tt.failCount, &localCfg, tt.baseline, tt.rebootAllowed, "budget exhausted", tt.inStartupGrace)
			if dec.Stage != tt.expectedStage {
				t.Errorf("expected stage %d, got %d", tt.expectedStage, dec.Stage)
			}
			if dec.ActionAllowed != tt.expectedAllowed {
				t.Errorf("expected actionAllowed %t, got %t", tt.expectedAllowed, dec.ActionAllowed)
			}
			if dec.ActionType != tt.expectedActionType {
				t.Errorf("expected actionType %q, got %q", tt.expectedActionType, dec.ActionType)
			}
		})
	}
}

func TestStatusReportAndJSON(t *testing.T) {
	w, _, _, _ := setupTestWatchdog(t)
	ctx := context.Background()

	// Text status
	txt := w.Status(ctx)
	if !strings.Contains(txt, "NETRISER STATUS REPORT") {
		t.Errorf("status text missing header: %s", txt)
	}

	// JSON status
	jsonStr, err := w.StatusJSON(ctx)
	if err != nil {
		t.Fatalf("StatusJSON failed: %v", err)
	}
	var rep StatusReport
	if err := json.Unmarshal([]byte(jsonStr), &rep); err != nil {
		t.Fatalf("failed to unmarshal StatusJSON output: %v", err)
	}
	if rep.PolicyRoutingTable != 200 {
		t.Errorf("expected table 200, got %d", rep.PolicyRoutingTable)
	}
}

func TestDryRunHealthyAndUnhealthy(t *testing.T) {
	w, cfg, _, chk := setupTestWatchdog(t)
	ctx := context.Background()

	// When healthy
	chk.fastResult.Healthy = true
	rep, err := w.EvaluateDryRun(ctx)
	if err != nil {
		t.Fatalf("EvaluateDryRun failed: %v", err)
	}
	if !rep.Healthy {
		t.Errorf("expected healthy dry-run")
	}
	if rep.EscalationStage != 0 {
		t.Errorf("expected stage 0 when healthy, got %d", rep.EscalationStage)
	}

	// When unhealthy and failCount reaches Stage 1
	chk.fastResult.Healthy = false
	w.writeFailCount(cfg.FailThresholdStage1 - 1)
	rep, err = w.EvaluateDryRun(ctx)
	if err != nil {
		t.Fatalf("EvaluateDryRun failed: %v", err)
	}
	if rep.Healthy {
		t.Errorf("expected unhealthy dry-run")
	}
	if rep.EscalationStage != 1 {
		t.Errorf("expected stage 1 in dry-run, got %d", rep.EscalationStage)
	}
	if len(rep.PlannedActions) == 0 {
		t.Errorf("expected planned actions in dry-run report")
	}
}

func TestValidateConfiguration(t *testing.T) {
	w, cfg, _, _ := setupTestWatchdog(t)
	ctx := context.Background()

	rep := w.ValidateConfiguration(ctx)
	if !rep.Valid {
		t.Errorf("expected valid config, got errors: %v", rep.Errors)
	}

	// Test invalid interval
	cfg.CheckIntervalSec = -5
	rep = w.ValidateConfiguration(ctx)
	if rep.Valid {
		t.Errorf("expected invalid config for negative interval")
	}
}

func TestUnhealthyDiscoveryCannotReplaceConfirmedBaselineOrQuarantine(t *testing.T) {
	for _, failCount := range []int{2, 3, 4} {
		t.Run(fmt.Sprint(failCount), func(t *testing.T) {
			w, cfg, engine, _ := setupTestWatchdog(t)
			confirmed := netengine.Baseline{Interface: "eth0", IP: "198.51.100.20", Gateway: "192.168.0.1"}
			netengine.SaveBaseline(cfg.StateDir, confirmed)
			w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, FailCount: failCount, Baseline: confirmed})
			engine.overrideBaseline = true
			engine.baseline = netengine.Baseline{Interface: "ens4", IP: "192.168.40.20", Source: netengine.BaselineSourceAuto}
			engine.baselineErr = errors.New("no WAN gateway")
			_, err := w.RunCheckCycle(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if engine.policyCalled || engine.cleanCalled || engine.quarantineCalled || engine.restartCalled || engine.rebootCalled {
				t.Fatal("unsafe discovery authorized remediation")
			}
			saved, err := netengine.LoadSavedBaseline(cfg.StateDir)
			if err != nil || saved != confirmed {
				t.Fatalf("confirmed baseline overwritten: %+v %v", saved, err)
			}
		})
	}
}

func TestNetworkRestartFailureIsReported(t *testing.T) {
	w, _, engine, _ := setupTestWatchdog(t)
	w.writeFailCount(3)
	engine.restartErr = errors.New("networkctl failed")
	report, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, act := range report.ActionsTaken {
		if act.Type == netengine.ActionRestartStack {
			if act.Status != netengine.ActionFailed || act.Error != "networkctl failed" {
				t.Fatalf("restart falsely reported successful: %+v", act)
			}
			return
		}
	}
	t.Fatal("restart result missing")
}

func TestQuarantineExpiresEvenWhenInternetRemainsDown(t *testing.T) {
	w, _, engine, _ := setupTestWatchdog(t)
	old := w.clock.Now().Add(-11 * time.Minute)
	w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, QuarantinedServices: []ServiceQuarantineRecord{
		{Name: "nebula", QuarantinedAt: old}, {Name: "tailscaled", QuarantinedAt: old},
	}})
	report, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy {
		t.Fatal("outage incorrectly marked healthy")
	}
	state, _ := w.stateMgr.LoadState()
	if len(engine.restoredServices) != 1 || engine.restoredServices[0] != "nebula" || len(state.QuarantinedServices) != 1 || state.QuarantinedServices[0].Name != "tailscaled" {
		t.Fatalf("expiry did not restore exactly one service: %v %+v", engine.restoredServices, state)
	}
}

func TestFailedServiceRestoreRemainsTracked(t *testing.T) {
	w, _, engine, checker := setupTestWatchdog(t)
	checker.fastResult = canary.HealthResult{Healthy: true}
	engine.restoreErr = errors.New("service could not start")
	w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, QuarantinedServices: []ServiceQuarantineRecord{{Name: "nebula", QuarantinedAt: w.clock.Now().Add(-time.Minute)}}})
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ := w.stateMgr.LoadState()
	if len(state.QuarantinedServices) != 1 || state.QuarantinedServices[0].Attempts != 1 {
		t.Fatalf("lost failed service recovery: %+v", state)
	}
}

func TestKnownAddresslessWANCanReconfigureButCannotChangeRoutes(t *testing.T) {
	w, _, engine, _ := setupTestWatchdog(t)
	w.writeFailCount(3)
	engine.overrideBaseline = true
	engine.baseline = netengine.Baseline{Interface: "eth0", Source: netengine.BaselineSourceCached}
	engine.baselineErr = errors.New("WAN address lost")
	report, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.RemediationStage != 3 || !engine.restartCalled || engine.cleanCalled || engine.quarantineCalled || engine.policyCalled {
		t.Fatalf("invalid addressless recovery: %+v", report)
	}
}

func TestExpiredQuarantineIgnoresLongBackoffAndDoesNotStarveOtherServices(t *testing.T) {
	w, cfg, engine, _ := setupTestWatchdog(t)
	cfg.AllowServiceQuarantine = false // Test release fairness without creating new quarantines.
	old := w.clock.Now().Add(-11 * time.Minute)
	w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, QuarantinedServices: []ServiceQuarantineRecord{
		{Name: "broken", QuarantinedAt: old, NextRetryAfter: w.clock.Now().Add(2 * time.Hour)},
		{Name: "nebula", QuarantinedAt: old},
	}})
	engine.restoreErr = errors.New("first service broken")
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ := w.stateMgr.LoadState()
	if len(state.QuarantinedServices) != 2 || state.QuarantinedServices[0].Name != "nebula" {
		t.Fatalf("failed restore starves other overlays: %+v", state)
	}
	engine.restoreErr = nil
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ = w.stateMgr.LoadState()
	if len(state.QuarantinedServices) != 1 || state.QuarantinedServices[0].Name != "broken" {
		t.Fatalf("other overlay not released: %+v", state)
	}
}

// Windows stops a WireGuard kill-switch tunnel during stage 1 route cleanup;
// the stopped service must be recorded so recovery restarts it later.
func TestStageOneOverlayStopIsRecordedForRestore(t *testing.T) {
	w, _, engine, _ := setupTestWatchdog(t)
	engine.cleanActions = []netengine.ActionResult{
		{Type: netengine.ActionQuarantineService, Target: "WireGuardTunnel$wg-test", Status: netengine.ActionExecuted},
		{Type: netengine.ActionQuarantineService, Target: "all", Status: netengine.ActionSkipped},
	}
	w.writeFailCount(0)
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ := w.stateMgr.LoadState()
	if state == nil || len(state.QuarantinedServices) != 1 || state.QuarantinedServices[0].Name != "WireGuardTunnel$wg-test" {
		t.Fatalf("stage 1 overlay stop not recorded: %+v", state)
	}
}

// A restart that cuts connectivity is retried at most max_restore_attempts
// times; the service is then left stopped and not released during outages.
func TestQuarantineRestoreGivesUpAfterMaxAttempts(t *testing.T) {
	w, cfg, engine, _ := setupTestWatchdog(t)
	cfg.MaxRestoreAttempts = 3
	healthy := false
	w.SetChecker(&dynamicChecker{onCheckFast: func(context.Context) canary.HealthResult {
		healthy = !healthy // healthy before each restore, broken right after it
		return canary.HealthResult{Healthy: healthy}
	}})
	svc := "WireGuardTunnel$wg-test"
	w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, QuarantinedServices: []ServiceQuarantineRecord{
		{Name: svc, QuarantinedAt: w.clock.Now().Add(-time.Hour), NextRetryAfter: w.clock.Now().Add(-time.Minute)},
	}})
	for cycle := 1; cycle <= 4; cycle++ {
		if _, err := w.RunCheckCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		state, _ := w.stateMgr.LoadState()
		if len(state.QuarantinedServices) != 1 {
			t.Fatalf("cycle %d: record lost: %+v", cycle, state.QuarantinedServices)
		}
		rec := state.QuarantinedServices[0]
		if want := cycle >= 3; rec.GaveUp != want {
			t.Fatalf("cycle %d: gave up = %v, attempts %d", cycle, rec.GaveUp, rec.Attempts)
		}
		state.QuarantinedServices[0].NextRetryAfter = w.clock.Now().Add(-time.Minute)
		w.stateMgr.SaveState(state)
	}
	if len(engine.restoredServices) != 3 {
		t.Fatalf("restarted %d times, want 3", len(engine.restoredServices))
	}

	// An outage must not release the culprit either.
	w.SetChecker(&dynamicChecker{})
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(engine.restoredServices) != 3 {
		t.Fatalf("released during outage: %v", engine.restoredServices)
	}
	if out := w.Status(context.Background()); !strings.Contains(out, "left stopped after 3 failed restarts") {
		t.Fatalf("status does not explain the stopped service:\n%s", out)
	}
}

// When the user starts a given-up service and NetRiser has to stop it again,
// the new incident gets a fresh restart budget.
func TestStoppingGivenUpServiceAgainResetsBudget(t *testing.T) {
	w, _, _, _ := setupTestWatchdog(t)
	svc := "WireGuardTunnel$wg-test"
	w.stateMgr.SaveState(&WatchdogState{Version: CurrentStateVersion, QuarantinedServices: []ServiceQuarantineRecord{
		{Name: svc, Attempts: 3, GaveUp: true},
	}})
	w.recordQuarantine([]netengine.ActionResult{{Type: netengine.ActionQuarantineService, Target: svc, Status: netengine.ActionExecuted}})
	state, _ := w.stateMgr.LoadState()
	if rec := state.QuarantinedServices[0]; rec.GaveUp || rec.Attempts != 0 || rec.NextRetryAfter.IsZero() {
		t.Fatalf("budget not reset: %+v", rec)
	}
}

func uplinkOnly(cfg *config.Config) {
	no := false
	cfg.FullTunnel = &no
}

// On a host declared without a full tunnel, a VPN that takes over the default
// route is removed while the internet still works and is never restarted.
func TestUplinkOnlyRemovesVPNDefaultRouteWhileHealthy(t *testing.T) {
	w, cfg, engine, checker := setupTestWatchdog(t)
	uplinkOnly(cfg)
	checker.fastResult = canary.HealthResult{Healthy: true}
	engine.rogue = []string{"0.0.0.0/0 on wg-test"}
	engine.cleanActions = []netengine.ActionResult{{Type: netengine.ActionQuarantineService, Target: "WireGuardTunnel$wg-test", Status: netengine.ActionExecuted}}
	rep, err := w.RunCheckCycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !engine.cleanCalled || !rep.Healthy || !rep.Remediated {
		t.Fatalf("rogue VPN route not removed while healthy: clean=%v %+v", engine.cleanCalled, rep)
	}
	state, _ := w.stateMgr.LoadState()
	if len(state.QuarantinedServices) != 1 || !state.QuarantinedServices[0].Enforced {
		t.Fatalf("VPN not recorded as kept stopped: %+v", state.QuarantinedServices)
	}

	// Later healthy cycles never restart it, even when its retry time passed.
	engine.rogue, engine.cleanCalled = nil, false
	state.QuarantinedServices[0].NextRetryAfter = w.clock.Now().Add(-time.Hour)
	state.QuarantinedServices[0].QuarantinedAt = w.clock.Now().Add(-time.Hour)
	w.stateMgr.SaveState(state)
	for i := 0; i < 2; i++ {
		if _, err := w.RunCheckCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	checker.fastResult = canary.HealthResult{Healthy: false} // nor during an outage
	cfg.AllowServiceQuarantine, cfg.AllowRouteSanitation = false, false
	if _, err := w.RunCheckCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if engine.restoreCalled {
		t.Fatalf("restarted a VPN on a host without a full tunnel: %v", engine.restoredServices)
	}
	if out := w.Status(context.Background()); !strings.Contains(out, "host without a full tunnel; not restarted") {
		t.Fatalf("status does not explain the stopped VPN:\n%s", out)
	}
}

// Without the setup answer (configurations from before 1.3.2), observation
// mode, or route sanitation, a healthy host is left alone.
func TestUplinkOnlyEnforcementRequiresAnswerAndPermission(t *testing.T) {
	for name, adjust := range map[string]func(*config.Config){
		"unanswered":  func(c *config.Config) {},
		"full tunnel": func(c *config.Config) { yes := true; c.FullTunnel = &yes },
		"observation": func(c *config.Config) { uplinkOnly(c); c.ObservationMode = true },
		"no routes":   func(c *config.Config) { uplinkOnly(c); c.AllowRouteSanitation = false },
	} {
		t.Run(name, func(t *testing.T) {
			w, cfg, engine, checker := setupTestWatchdog(t)
			adjust(cfg)
			checker.fastResult = canary.HealthResult{Healthy: true}
			engine.rogue = []string{"0.0.0.0/0 on wg-test"}
			if _, err := w.RunCheckCycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			if engine.cleanCalled {
				t.Fatal("changed routes on a healthy host")
			}
		})
	}
}

// A mesh overlay stopped on such a host is still restarted: it is the access
// path, and enforcement removes its default route again if needed.
func TestUplinkOnlyStillRestoresMeshOverlays(t *testing.T) {
	w, cfg, _, _ := setupTestWatchdog(t)
	uplinkOnly(cfg)
	w.recordQuarantine([]netengine.ActionResult{
		{Type: netengine.ActionQuarantineService, Target: "tailscaled", Status: netengine.ActionExecuted},
		{Type: netengine.ActionQuarantineService, Target: "wg-quick@wg0", Status: netengine.ActionExecuted},
	})
	state, _ := w.stateMgr.LoadState()
	got := map[string]bool{}
	for _, rec := range state.QuarantinedServices {
		got[rec.Name] = rec.Enforced
	}
	if got["tailscaled"] || !got["wg-quick@wg0"] {
		t.Fatalf("wrong restart policy: %v", got)
	}
}
