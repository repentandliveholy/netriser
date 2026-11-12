package watchdog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/canary"
	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
)

type Watchdog struct {
	cfg           *config.Config
	configPath    string
	engine        netengine.NetworkEngine
	checker       ConnectivityChecker
	clock         Clock
	logger        *Logger
	startedAt     time.Time
	rebootTracker *RebootTracker
	stateMgr      *StateManager
	// lastRogue suppresses repeating the same observation-mode warning.
	lastRogue string
	version   string
}

type CheckReport struct {
	IncidentID       string                   `json:"incident_id,omitempty"`
	InitialHealthy   bool                     `json:"initial_healthy"`
	InitialFailCount int                      `json:"initial_fail_count"`
	Healthy          bool                     `json:"healthy"`
	FailCount        int                      `json:"fail_count"`
	Baseline         netengine.Baseline       `json:"baseline"`
	CanaryResult     canary.HealthResult      `json:"canary_result"`
	PostCanaryResult *canary.HealthResult     `json:"post_canary_result,omitempty"`
	Remediated       bool                     `json:"remediated"`
	AccessLost       bool                     `json:"access_lost,omitempty"`
	RemediationStage int                      `json:"remediation_stage"`
	StageReason      string                   `json:"stage_reason,omitempty"`
	ActionsTaken     []netengine.ActionResult `json:"actions_taken,omitempty"`
	Timestamp        time.Time                `json:"timestamp"`
}

// ActionStrings returns human-readable action summaries.
func (r *CheckReport) ActionStrings() []string {
	res := make([]string, len(r.ActionsTaken))
	for i, a := range r.ActionsTaken {
		res[i] = a.String()
	}
	return res
}

func NewWatchdog(cfg *config.Config, verbose bool) *Watchdog {
	logger := NewLogger(cfg.LogFile, verbose)
	engine := netengine.NewEngine(cfg)
	checker := canary.NewChecker(cfg)
	clock := RealClock{}
	tracker := NewRebootTracker(cfg.StateDir, clock)
	stateMgr := NewStateManager(cfg.StateDir)

	return &Watchdog{
		cfg:           cfg,
		engine:        engine,
		checker:       checker,
		clock:         clock,
		logger:        logger,
		startedAt:     clock.Now(),
		rebootTracker: tracker,
		stateMgr:      stateMgr,
	}
}

// NewWatchdogWithDeps allows full dependency injection for deterministic testing and isolation.
func NewWatchdogWithDeps(cfg *config.Config, engine netengine.NetworkEngine, checker ConnectivityChecker, clock Clock, logger *Logger) *Watchdog {
	if clock == nil {
		clock = RealClock{}
	}
	if logger == nil {
		logger = NewLogger("", false)
	}
	tracker := NewRebootTracker(cfg.StateDir, clock)
	stateMgr := NewStateManager(cfg.StateDir)

	return &Watchdog{
		cfg:           cfg,
		engine:        engine,
		checker:       checker,
		clock:         clock,
		logger:        logger,
		startedAt:     clock.Now(),
		rebootTracker: tracker,
		stateMgr:      stateMgr,
	}
}

// SetJSONMode directs console log output to Stderr so Stdout contains clean JSON.
func (w *Watchdog) SetJSONMode(jsonMode bool) {
	if w.logger != nil {
		w.logger.SetJSONMode(jsonMode)
	}
}

// SetConfigPath records the explicit configuration file path used.
func (w *Watchdog) SetConfigPath(p string) {
	w.configPath = p
}

// SetVersion records the program version for the start and stop log lines.
func (w *Watchdog) SetVersion(v string) {
	w.version = v
}

func (w *Watchdog) versionLabel() string {
	if w.version == "" {
		return "dev"
	}
	return w.version
}

// LogStarted writes one line when the daemon starts, so that "nr logs" shows
// that the service runs, which version and which configuration it uses; a
// healthy daemon is otherwise silent.
func (w *Watchdog) LogStarted() {
	path := w.configPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	mode := "recovery on"
	if w.cfg.ObservationMode {
		mode = "observation mode (no recovery actions)"
	}
	w.logger.Info("NetRiser %s started: configuration %s; %s; default route: %s", w.versionLabel(), path, mode, config.DefaultRoutePolicy(w.cfg))
}

// LogStopped writes one line when the daemon stops.
func (w *Watchdog) LogStopped() {
	w.logger.Info("NetRiser %s stopped.", w.versionLabel())
}

// LogRelocated records files moved from the old Mesh Watchdog paths at start.
func (w *Watchdog) LogRelocated(moved []string, err error) {
	if err != nil {
		w.logger.Warn("Moving legacy mesh-watchdog files failed, the old paths stay in use: %v", err)
	}
	for _, line := range moved {
		w.logger.Info("Moved legacy mesh-watchdog files: %s", line)
	}
}

// SetEngine overrides network engine.
func (w *Watchdog) SetEngine(e netengine.NetworkEngine) {
	w.engine = e
}

// SetChecker overrides connectivity checker.
func (w *Watchdog) SetChecker(c ConnectivityChecker) {
	w.checker = c
}

// SetClock overrides clock.
func (w *Watchdog) SetClock(c Clock) {
	w.clock = c
	w.rebootTracker.clock = c
}

// SetStartedAt overrides startup timestamp (useful for testing startup grace).
func (w *Watchdog) SetStartedAt(t time.Time) {
	w.startedAt = t
}

// SetRebootTracker overrides reboot tracker.
func (w *Watchdog) SetRebootTracker(t *RebootTracker) {
	w.rebootTracker = t
}

// SetStateManager overrides state manager.
func (w *Watchdog) SetStateManager(sm *StateManager) {
	w.stateMgr = sm
}

func (w *Watchdog) readFailCount() int {
	state, err := w.stateMgr.LoadStateReadOnly()
	if err != nil || state == nil {
		return 0
	}
	return state.FailCount
}

func (w *Watchdog) writeFailCount(count int) error {
	state, err := w.stateMgr.LoadState()
	if err != nil || state == nil {
		state = &WatchdogState{Version: CurrentStateVersion}
	}
	if count > 0 {
		if state.FailCount == 0 || state.FirstFailedAt.IsZero() {
			state.FirstFailedAt = w.clock.Now()
		}
		state.LastFailedAt = w.clock.Now()
	} else {
		state.FirstFailedAt = time.Time{}
		state.RebootedInOutage, state.RecoveryPaused, state.ProbesBlocked = false, false, false
	}
	state.FailCount = count
	return w.stateMgr.SaveState(state)
}

func (w *Watchdog) readQuarantinedServiceNames() []string {
	state, err := w.stateMgr.LoadStateReadOnly()
	if err != nil || state == nil {
		return nil
	}
	var names []string
	for _, q := range state.QuarantinedServices {
		names = append(names, q.Name)
	}
	return names
}

const MaxIncidentTotalBytes = 10 * 1024 * 1024 // 10 MB

func (w *Watchdog) pruneIncidents(maxKeep int) {
	if maxKeep <= 0 {
		maxKeep = 10
	}
	entries, err := os.ReadDir(w.cfg.IncidentDir)
	if err != nil {
		return
	}
	type incidentFile struct {
		path string
		size int64
	}
	var logs []incidentFile
	var totalSize int64

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "incident-") && strings.HasSuffix(entry.Name(), ".log") {
			fullPath := filepath.Join(w.cfg.IncidentDir, entry.Name())
			fi, fErr := entry.Info()
			sz := int64(0)
			if fErr == nil {
				sz = fi.Size()
			}
			logs = append(logs, incidentFile{path: fullPath, size: sz})
			totalSize += sz
		}
	}

	sort.Slice(logs, func(i, j int) bool {
		return logs[i].path < logs[j].path
	})

	for len(logs) > maxKeep || (totalSize > MaxIncidentTotalBytes && len(logs) > 1) {
		removed := logs[0]
		_ = os.Remove(removed.path)
		totalSize -= removed.size
		logs = logs[1:]
	}
}

func (w *Watchdog) dumpIncident(ctx context.Context, failCount int, res canary.HealthResult, b netengine.Baseline) string {
	_ = os.MkdirAll(w.cfg.IncidentDir, 0750)
	ts := w.clock.Now().Format("20060102-150405")
	filename := filepath.Join(w.cfg.IncidentDir, fmt.Sprintf("incident-%s.log", ts))

	diag, _ := w.engine.DumpDiagnostics(ctx, b)

	var buf bytes.Buffer
	buf.WriteString("======================================================================\n")
	buf.WriteString("                   NETRISER INCIDENT REPORT                      \n")
	buf.WriteString("======================================================================\n")
	buf.WriteString(fmt.Sprintf("Timestamp:           %s\n", w.clock.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("Consecutive Failure: #%d\n", failCount))
	buf.WriteString(fmt.Sprintf("Physical Baseline:   %s\n", b.String()))
	buf.WriteString("\n--- Canary Probe Results ---\n")
	for _, det := range res.Details {
		status := "FAIL"
		if det.Success {
			status = "OK"
		}
		errMsg := ""
		if det.Error != nil {
			errMsg = fmt.Sprintf(" (error: %v)", det.Error)
		}
		buf.WriteString(fmt.Sprintf("  [%s] %-20s latency=%-8v%s\n", status, det.Target, det.Latency.Round(time.Millisecond), errMsg))
	}
	buf.WriteString("\n")
	buf.WriteString(diag)

	if err := os.WriteFile(filename, buf.Bytes(), 0640); err != nil {
		w.logger.Error("Failed to write diagnostic incident snapshot to %s: %v", filename, err)
	} else {
		w.logger.Warn("Diagnostic incident snapshot saved to %s", filename)
	}
	w.pruneIncidents(10)

	return filename
}

func (w *Watchdog) RunCheckCycle(ctx context.Context) (*CheckReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	_ = w.cfg.EnsureDirectories()

	lock, err := AcquireLock(w.cfg.LockFile)
	if err != nil {
		if err == ErrAlreadyRunning {
			w.logger.Warn("Another NetRiser instance is currently running. Skipping cycle.")
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	defer lock.Unlock()

	// 1. Detect baseline and ensure Level 1 Policy Routing
	state, _ := w.stateMgr.LoadState()
	if state == nil {
		state = &WatchdogState{Version: CurrentStateVersion}
	}

	baseline, bErr := w.engine.DetectBaseline(ctx)
	if bErr != nil {
		w.logger.Warn("Baseline detection warning: %v", bErr)
	}

	currentFails := state.FailCount

	// 2. Perform fast parallel connectivity test
	canaryResult := w.checker.CheckFast(ctx)

	report := &CheckReport{
		Timestamp:        w.clock.Now(),
		InitialHealthy:   canaryResult.Healthy,
		InitialFailCount: currentFails,
		Healthy:          canaryResult.Healthy,
		FailCount:        currentFails,
		Baseline:         baseline,
		CanaryResult:     canaryResult,
		Remediated:       false,
		ActionsTaken:     make([]netengine.ActionResult, 0),
	}

	if canaryResult.DNSOnlyFailure() {
		return w.recoverDNS(ctx, report)
	}

	// 3. Status Healthy -> Auto-recovery of quarantined services if needed
	if canaryResult.Healthy {
		if !w.cfg.ObservationMode && canaryResult.DNS != nil && canaryResult.DNS.Healthy {
			if dns, ok := w.engine.(netengine.DNSRecoveryEngine); ok {
				if err := dns.CaptureDNSBaseline(ctx); err != nil {
					w.logger.Warn("DNS baseline not saved: %v", err)
				}
			}
		}
		if bErr == nil && baseline.IsValid() && !w.cfg.ObservationMode {
			baseline.LastConfirmed = w.clock.Now()
			if err := netengine.SaveBaseline(w.cfg.StateDir, baseline); err != nil {
				return report, fmt.Errorf("confirm baseline: %w", err)
			}
			state.Baseline = baseline
			if err := w.stateMgr.SaveState(state); err != nil {
				return report, err
			}
			if err := w.engine.ApplyPolicyRouting(ctx, baseline); err != nil {
				w.logger.Warn("Policy routing failed: %v", err)
			}
		}
		if w.enforceUplinkOnly(ctx, baseline, bErr, report) {
			if fresh, _ := w.stateMgr.LoadState(); fresh != nil {
				state = fresh
			}
		}
		if w.checkAccess(ctx, canaryResult, baseline, bErr, report) {
			if fresh, _ := w.stateMgr.LoadState(); fresh != nil {
				state = fresh
			}
		}
		if len(state.QuarantinedServices) > 0 && !w.cfg.ObservationMode {
			var remaining []ServiceQuarantineRecord
			broken := false
			recoveredCount := 0

			for idx, rec := range state.QuarantinedServices {
				if rec.GaveUp || rec.Enforced || broken || recoveredCount >= 1 || w.clock.Now().Before(rec.NextRetryAfter) {
					remaining = append(remaining, rec)
					continue
				}

				w.logger.Info("Attempting sequential recovery of quarantined service: %s (attempt #%d)", rec.Name, rec.Attempts+1)
				rec.Attempts++
				recoveredCount++

				_, rErr := w.engine.RestoreMeshServices(ctx, []string{rec.Name})
				if rErr != nil {
					w.logger.Warn("Service %s failed to restart cleanly: %v", rec.Name, rErr)
					rec.NextRetryAfter = w.clock.Now().Add(5 * time.Minute)
					remaining = append(remaining, rec)
					continue
				}

				if sErr := w.clock.Sleep(ctx, 3*time.Second); sErr != nil {
					remaining = append(remaining, rec)
					state.QuarantinedServices = append(remaining, state.QuarantinedServices[idx+1:]...)
					_ = w.stateMgr.SaveState(state)
					return report, sErr
				}

				postRestoreCheck := w.checker.CheckFast(ctx)
				if postRestoreCheck.DNSOnlyFailure() {
					state.QuarantinedServices = append(remaining, state.QuarantinedServices[idx+1:]...)
					if err := w.stateMgr.SaveState(state); err != nil {
						return report, err
					}
					report.CanaryResult, report.Healthy = postRestoreCheck, false
					return w.recoverDNS(ctx, report)
				}
				if postRestoreCheck.Healthy && !postRestoreCheck.AccessLost() {
					w.logger.Info("Service %s successfully restored and network remains healthy!", rec.Name)
				} else {
					if postRestoreCheck.AccessLost() {
						w.logger.Warn("Restoring %s cut remote access (no access address answers)! Re-quarantining with exponential backoff.", rec.Name)
					} else {
						w.logger.Warn("Restoring %s triggered network disruption! Re-quarantining with exponential backoff.", rec.Name)
					}
					w.cfg.SetVPNBypassActive(true)
					if w.cfg.AllowServiceQuarantine {
						_, _ = w.engine.QuarantineMeshServices(ctx)
					}
					if w.cfg.AllowRouteSanitation && bErr == nil && baseline.IsValid() {
						_, _ = w.engine.SurgicalCleanRoutes(ctx, baseline)
					}
					w.cfg.SetVPNBypassActive(false)
					if limit := w.cfg.MaxRestoreAttempts; limit > 0 && rec.Attempts >= limit {
						rec.GaveUp = true
						w.logger.Warn("Gave up restoring %s after %d attempts: each restart cut connectivity. It stays stopped; start it yourself once its server is reachable.", rec.Name, rec.Attempts)
					} else {
						backoffMins := 5 * (1 << (rec.Attempts - 1))
						if backoffMins > 120 {
							backoffMins = 120
						}
						rec.NextRetryAfter = w.clock.Now().Add(time.Duration(backoffMins) * time.Minute)
					}
					remaining = append(remaining, rec)
					broken = true
				}
			}

			state.QuarantinedServices = remaining
			if err := w.stateMgr.SaveState(state); err != nil {
				w.logger.Error("Failed to update quarantine state: %v", err)
			}

			if broken {
				report.Healthy = false
				return report, nil
			}
		}

		if currentFails > 0 {
			w.logger.Info("Network connectivity RESTORED after %d failed check(s). Resetting counter.", currentFails)
			if err := w.writeFailCount(0); err != nil {
				w.logger.Error("Failed to reset fail count state: %v", err)
			}
			report.FailCount = 0
		}
		return report, nil
	}

	if !w.cfg.ObservationMode {
		for i, rec := range state.QuarantinedServices {
			// A service whose restart already cut connectivity caused the
			// problem; releasing it during an outage would only reset its
			// restart limit.
			if rec.GaveUp || rec.Enforced || rec.Attempts > 0 {
				continue
			}
			if !rec.QuarantinedAt.IsZero() && w.clock.Now().Sub(rec.QuarantinedAt) < 10*time.Minute {
				continue
			}
			if w.clock.Now().Before(rec.ReleaseRetryAfter) {
				continue
			}
			actions, restoreErr := w.engine.RestoreMeshServices(ctx, []string{rec.Name})
			report.ActionsTaken = append(report.ActionsTaken, actions...)
			if restoreErr == nil {
				state.QuarantinedServices = append(state.QuarantinedServices[:i], state.QuarantinedServices[i+1:]...)
			} else {
				rec.ReleaseRetryAfter = w.clock.Now().Add(time.Minute)
				// Put failed services last so one broken unit cannot starve other overlays.
				state.QuarantinedServices = append(append(state.QuarantinedServices[:i], state.QuarantinedServices[i+1:]...), rec)
				w.logger.Warn("Expired quarantine restore failed for %s: %v", rec.Name, restoreErr)
			}
			if err := w.stateMgr.SaveState(state); err != nil {
				return report, err
			}
			break // Restore one overlay per cycle, even when public canaries are down.
		}
	}
	// 4. Status Unhealthy -> Register failure
	currentFails++
	if err := w.writeFailCount(currentFails); err != nil {
		w.logger.Error("CRITICAL: Failed to write fail count state (%v). Aborting destructive escalation.", err)
		return report, fmt.Errorf("state persistence failure: %w", err)
	}
	report.IncidentID = fmt.Sprintf("inc-%d-%d", w.clock.Now().Unix(), currentFails)
	report.Healthy = false
	report.FailCount = currentFails
	w.logger.Warn("Network connectivity check FAILED (Consecutive failures: %d, Incident ID: %s)", currentFails, report.IncidentID)

	// Dump diagnostics snapshot
	w.dumpIncident(ctx, currentFails, canaryResult, baseline)

	// 5. Calculate Escalation Decision
	inStartupGrace := false
	if w.cfg.StartupGraceSec > 0 {
		startupGraceDuration := time.Duration(w.cfg.StartupGraceSec) * time.Second
		if w.clock.Now().Sub(w.startedAt) < startupGraceDuration {
			inStartupGrace = true
		}
	}

	rebootWindow := time.Duration(w.cfg.RebootBudgetWindowSec) * time.Second
	rebootAllowed, budgetReason := w.rebootTracker.CanReboot(w.cfg.RebootBudgetCount, rebootWindow)
	rebootAllowed, budgetReason = w.guardRebootOutage(state, rebootAllowed, budgetReason)

	actionBaseline := baseline
	if bErr != nil {
		actionBaseline.IP = ""
	}
	decision := DecideEscalation(currentFails, w.cfg, actionBaseline, rebootAllowed, budgetReason, inStartupGrace)
	report.RemediationStage = decision.Stage
	report.StageReason = decision.Reason
	if decision.SkipReason != "" {
		report.StageReason = decision.SkipReason
	}

	if decision.Stage >= 3 {
		if blocked, why := w.probesBlocked(ctx, canaryResult, baseline); blocked {
			w.holdForBlockedProbes(state, why)
			report.StageReason = "internet probes look blocked (" + why + "); network restart and reboot held back"
			return report, nil
		}
	}

	if decision.Stage == 4 && state.RebootedInOutage {
		// The reboot and another round of stages 1-3 did not restore access:
		// stop acting and keep checking until connectivity returns.
		if !state.RecoveryPaused {
			w.logger.Recovery("Connectivity did not return after the emergency reboot and another round of recovery stages. NetRiser stops acting and keeps checking; it resumes when connectivity returns.")
			if fresh, _ := w.stateMgr.LoadState(); fresh != nil {
				fresh.RecoveryPaused = true
				_ = w.stateMgr.SaveState(fresh)
			}
		}
		report.StageReason = "recovery paused after an emergency reboot; waiting for connectivity"
		return report, nil
	}

	w.logger.Recovery("[Stage %d] %s", decision.Stage, decision.Reason)

	// On a full-tunnel host where access comes first, a VPN on
	// allowed_default_interfaces may be bypassed while recovering.
	w.cfg.SetVPNBypassActive(true)
	defer w.cfg.SetVPNBypassActive(false)

	switch decision.Stage {
	case 4:
		if !decision.ActionAllowed {
			report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{
				Type:        netengine.ActionReboot,
				Target:      "host",
				Status:      netengine.ActionSkipped,
				Description: fmt.Sprintf("Emergency reboot skipped: %s", decision.SkipReason),
			})
			if w.cfg.AllowNetworkRestart && ((bErr == nil && baseline.IsValid()) || baseline.HasKnownInterface()) {
				report.ActionsTaken = append(report.ActionsTaken, w.restartNetwork(ctx, baseline))
			}
			if w.cfg.AllowRouteSanitation && bErr == nil && baseline.IsValid() {
				actions, cleanErr := w.engine.SurgicalCleanRoutes(ctx, baseline)
				if cleanErr != nil {
					actions = append(actions, netengine.ActionResult{Type: netengine.ActionCleanRoute, Target: "routes", Status: netengine.ActionFailed, Error: cleanErr.Error()})
				}
				report.ActionsTaken = append(report.ActionsTaken, actions...)
			}
		} else {
			// Pre-reboot grace window with context cancellation & final re-check
			w.logger.Recovery("[Stage 4] Pre-reboot grace window of %ds initiated...", w.cfg.RebootGraceSec)
			graceDuration := time.Duration(w.cfg.RebootGraceSec) * time.Second
			if err := w.clock.Sleep(ctx, graceDuration); err != nil {
				return report, err
			}

			// Pre-reboot verification check
			preRebootCheck := w.checker.CheckFast(ctx)
			if preRebootCheck.DNSOnlyFailure() {
				report.CanaryResult = preRebootCheck
				return w.recoverDNS(ctx, report)
			}
			if preRebootCheck.Healthy {
				w.logger.Info("Connectivity RESTORED during pre-reboot grace window! Aborting emergency host reboot.")
				_ = w.writeFailCount(0)
				report.Healthy = true
				report.Remediated = true
				report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{
					Type:        netengine.ActionReboot,
					Target:      "host",
					Status:      netengine.ActionSkipped,
					Description: "Reboot aborted: connectivity recovered during grace window",
				})
				return report, nil
			}

			// Proceed with reboot
			w.logger.Recovery("[Stage 4] Pre-reboot verification failed. Executing emergency host reboot...")
			_ = w.rebootTracker.RecordReboot()
			// After the restart, checks and stages 1-3 run again from the
			// start; no second reboot happens during this outage.
			if fresh, _ := w.stateMgr.LoadState(); fresh != nil {
				fresh.FailCount, fresh.RebootedInOutage, fresh.RecoveryPaused = 0, true, false
				if err := w.stateMgr.SaveState(fresh); err != nil {
					w.logger.Error("Could not record the reboot in state (%v); aborting the reboot.", err)
					return report, err
				}
			}
			report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{
				Type:        netengine.ActionReboot,
				Target:      "host",
				Status:      netengine.ActionExecuted,
				Description: "Executed emergency host reboot",
			})
			_ = w.engine.EmergencyReboot(ctx, fmt.Sprintf("unrecoverable network isolation after %d checks", currentFails))
		}

	case 3:
		if !decision.ActionAllowed {
			report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{
				Type:        netengine.ActionRestartStack,
				Target:      baseline.Interface,
				Status:      netengine.ActionSkipped,
				Description: fmt.Sprintf("Network restart skipped: %s", decision.SkipReason),
			})
		} else {
			report.ActionsTaken = append(report.ActionsTaken, w.restartNetwork(ctx, baseline))
		}
		if w.cfg.AllowRouteSanitation && bErr == nil && baseline.IsValid() {
			actions, cleanErr := w.engine.SurgicalCleanRoutes(ctx, baseline)
			if cleanErr != nil {
				actions = append(actions, netengine.ActionResult{Type: netengine.ActionCleanRoute, Target: "routes", Status: netengine.ActionFailed, Error: cleanErr.Error()})
			}
			report.ActionsTaken = append(report.ActionsTaken, actions...)
		}

	case 2:
		if !decision.ActionAllowed {
			report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{
				Type:        netengine.ActionQuarantineService,
				Target:      "all",
				Status:      netengine.ActionSkipped,
				Description: fmt.Sprintf("Service quarantine skipped: %s", decision.SkipReason),
			})
		} else {
			quarantinedActions, quarantineErr := w.engine.QuarantineMeshServices(ctx)
			if quarantineErr != nil {
				quarantinedActions = append(quarantinedActions, netengine.ActionResult{Type: netengine.ActionQuarantineService, Target: "all", Status: netengine.ActionSkipped, Error: quarantineErr.Error(), Description: "Preserved overlays: quarantine preconditions not met"})
			}
			report.ActionsTaken = append(report.ActionsTaken, quarantinedActions...)
		}
		if w.cfg.AllowRouteSanitation && bErr == nil && baseline.IsValid() {
			actions, cleanErr := w.engine.SurgicalCleanRoutes(ctx, baseline)
			if cleanErr != nil {
				actions = append(actions, netengine.ActionResult{Type: netengine.ActionCleanRoute, Target: "routes", Status: netengine.ActionFailed, Error: cleanErr.Error()})
			}
			report.ActionsTaken = append(report.ActionsTaken, actions...)
		}

	case 1:
		if !decision.ActionAllowed {
			report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{
				Type:        netengine.ActionCleanRoute,
				Target:      "routes",
				Status:      netengine.ActionSkipped,
				Description: fmt.Sprintf("Route sanitation skipped: %s", decision.SkipReason),
			})
		} else {
			actions, cleanErr := w.engine.SurgicalCleanRoutes(ctx, baseline)
			if cleanErr != nil {
				actions = append(actions, netengine.ActionResult{Type: netengine.ActionCleanRoute, Target: "routes", Status: netengine.ActionFailed, Error: cleanErr.Error()})
			}
			report.ActionsTaken = append(report.ActionsTaken, actions...)
		}

	default: // Stage 0
		w.logger.Info("[Stage 0] Failure count %d below threshold or observation mode active. No remediation attempted.", currentFails)
	}

	// Any stage may stop an overlay (Windows stops a WireGuard tunnel during
	// route cleanup); record it so recovery restarts it later.
	w.recordQuarantine(report.ActionsTaken)

	for _, act := range report.ActionsTaken {
		w.logger.Recovery("  - %s", act.String())
	}

	// 6. Post-remediation verification
	if decision.Stage > 0 && (decision.ActionAllowed || len(report.ActionsTaken) > 1) {
		if err := w.clock.Sleep(ctx, 2*time.Second); err != nil {
			return report, err
		}
		postCheck := w.checker.CheckFast(ctx)
		if postCheck.DNSOnlyFailure() {
			report.CanaryResult = postCheck
			return w.recoverDNS(ctx, report)
		}
		if postCheck.Healthy {
			w.logger.Info("Connectivity RESTORED by Stage %d remediation at failure count %d!", report.RemediationStage, currentFails)
			_ = w.writeFailCount(0)
			report.Healthy = true
			report.Remediated = true
			report.FailCount = 0
		} else {
			w.logger.Warn("Connectivity remains down after Stage %d remediation. Next cycle will escalate.", report.RemediationStage)
		}
	}

	return report, nil
}

// probesBlocked reports whether the failing internet probes look filtered
// while the network itself works (see canary.Checker.ProbesBlocked).
// It applies only when internet probes are configured and they failed.
func (w *Watchdog) probesBlocked(ctx context.Context, res canary.HealthResult, baseline netengine.Baseline) (bool, string) {
	pf, ok := w.checker.(probeFilterChecker)
	if !ok || res.InternetHealthy || (len(w.cfg.CanaryTargets) == 0 && w.cfg.HTTPFallbackURL == "") {
		return false, ""
	}
	return pf.ProbesBlocked(ctx, baseline.Gateway)
}

// holdForBlockedProbes logs that strong actions are held back; the full
// explanation once per outage, a short line on later checks.
func (w *Watchdog) holdForBlockedProbes(state *WatchdogState, why string) {
	if state.ProbesBlocked {
		w.logger.Recovery("Internet probes still do not answer, but %s. Network restart and reboot stay held back.", why)
		return
	}
	w.logger.Warn("The internet probes (canary_targets, http_fallback_url) do not answer, but %s. The network works; the probe addresses are probably blocked on this network. NetRiser does not restart the network or reboot for this and only keeps checking. Replace canary_targets with addresses that answer from this network: run `nr setup` or edit the configuration file.", why)
	if fresh, _ := w.stateMgr.LoadState(); fresh != nil {
		fresh.ProbesBlocked = true
		if err := w.stateMgr.SaveState(fresh); err != nil {
			w.logger.Error("Failed to record blocked probes in state: %v", err)
		}
	}
}

// keepStopped reports whether a stopped service must not be restarted: a
// full-tunnel VPN on a host configured without a full tunnel would only take
// over the default route again.
func (w *Watchdog) keepStopped(service string) bool {
	if !w.cfg.UplinkOnly() {
		return false
	}
	kind, ok := netengine.ServiceKind(service)
	return ok && kind == netengine.KindVPN
}

// enforceUplinkOnly removes overlay default routes on a host configured
// without a full tunnel, while connectivity is healthy. It reports whether it
// changed anything (the quarantine state may then have been updated).
func (w *Watchdog) enforceUplinkOnly(ctx context.Context, baseline netengine.Baseline, bErr error, report *CheckReport) bool {
	if !w.cfg.UplinkOnly() || !w.cfg.AllowRouteSanitation || bErr != nil || !baseline.IsValid() {
		return false
	}
	det, ok := w.engine.(netengine.RogueRouteDetector)
	if !ok {
		return false
	}
	rogue, err := det.RogueDefaultRoutes(ctx)
	if err != nil {
		w.logger.Warn("Default route ownership check failed: %v", err)
		return false
	}
	key := strings.Join(rogue, ", ")
	defer func() { w.lastRogue = key }()
	if len(rogue) == 0 {
		return false
	}
	if w.cfg.ObservationMode {
		if key != w.lastRogue {
			w.logger.Warn("[Observation] Default route taken over by %s on a host configured without a full tunnel; NetRiser would remove it now.", key)
		}
		return false
	}
	w.logger.Recovery("Default route taken over by %s on a host configured without a full tunnel (full_tunnel: false). Removing it.", key)
	actions, cleanErr := w.engine.SurgicalCleanRoutes(ctx, baseline)
	if cleanErr != nil {
		actions = append(actions, netengine.ActionResult{Type: netengine.ActionCleanRoute, Target: "routes", Status: netengine.ActionFailed, Error: cleanErr.Error()})
	}
	for _, act := range actions {
		w.logger.Recovery("  - %s", act.String())
	}
	report.ActionsTaken = append(report.ActionsTaken, actions...)
	report.Remediated = true
	w.recordQuarantine(actions)
	return true
}

// accessLossChecks is how many consecutive checks must find access lost
// before recovery acts, so that one missed answer is not acted on.
const accessLossChecks = 2

// checkAccess handles the access addresses (mesh_canaries) while the
// internet works. When none answers in accessLossChecks consecutive checks,
// a full-tunnel VPN is bypassed on hosts where access comes first; otherwise
// the loss is only logged. It reports whether the state was changed.
func (w *Watchdog) checkAccess(ctx context.Context, res canary.HealthResult, baseline netengine.Baseline, bErr error, report *CheckReport) bool {
	state, _ := w.stateMgr.LoadState()
	if state == nil {
		return false
	}
	if !res.AccessLost() {
		if state.AccessFailCount == 0 && !state.AccessActed {
			return false
		}
		if res.AccessChecked {
			w.logger.Info("Remote access restored: an access address answers again.")
		}
		state.AccessFailCount, state.AccessActed = 0, false
		_ = w.stateMgr.SaveState(state)
		return true
	}
	report.AccessLost = true
	state.AccessFailCount++
	if state.AccessFailCount == 1 {
		w.logger.Warn("Remote access check FAILED: the internet works, but none of the access addresses (%s) answers.", strings.Join(w.cfg.MeshCanaries, ", "))
	}
	act := state.AccessFailCount >= accessLossChecks && !state.AccessActed
	if act {
		state.AccessActed = true
	}
	if err := w.stateMgr.SaveState(state); err != nil || !act {
		return true
	}

	switch {
	case w.cfg.ObservationMode:
		w.logger.Warn("[Observation] Remote access is lost while the internet works; NetRiser would look for a VPN cutting the host off.")
	case !w.cfg.AccessFirst():
		reason := "no full-tunnel VPN may be bypassed on this host"
		if w.cfg.FullTunnel != nil && *w.cfg.FullTunnel {
			reason = "privacy comes first on this host, so the VPN is not bypassed"
		}
		w.logger.Warn("Remote access is lost while the internet works; %s. Recording only.", reason)
	case !w.cfg.AllowRouteSanitation || bErr != nil || !baseline.IsValid():
		w.logger.Warn("Remote access is lost while the internet works; route recovery is not possible now. Recording only.")
	default:
		det, ok := w.engine.(netengine.RogueRouteDetector)
		if !ok {
			return true
		}
		w.cfg.SetVPNBypassActive(true)
		defer w.cfg.SetVPNBypassActive(false)
		rogue, err := det.RogueDefaultRoutes(ctx)
		if err != nil || len(rogue) == 0 {
			w.logger.Warn("Remote access is lost while the internet works, but no VPN holds the default route. Recording only.")
			return true
		}
		w.logger.Recovery("Remote access is lost while %s holds the default route; access comes first on this host, so the VPN is bypassed.", strings.Join(rogue, ", "))
		actions, cleanErr := w.engine.SurgicalCleanRoutes(ctx, baseline)
		if cleanErr != nil {
			actions = append(actions, netengine.ActionResult{Type: netengine.ActionCleanRoute, Target: "routes", Status: netengine.ActionFailed, Error: cleanErr.Error()})
		}
		for _, a := range actions {
			w.logger.Recovery("  - %s", a.String())
		}
		report.ActionsTaken = append(report.ActionsTaken, actions...)
		report.Remediated = true
		w.recordQuarantine(actions)
	}
	return true
}

// recordQuarantine stores overlays stopped by remediation in the state.
func (w *Watchdog) recordQuarantine(actions []netengine.ActionResult) {
	var stopped []string
	for _, act := range actions {
		if act.Type == netengine.ActionQuarantineService && (act.Status == netengine.ActionExecuted || act.Status == netengine.ActionPartial) && act.Target != "" && act.Target != "all" {
			stopped = append(stopped, act.Target)
		}
	}
	if len(stopped) == 0 {
		return
	}
	curState, _ := w.stateMgr.LoadState()
	if curState == nil {
		curState = &WatchdogState{Version: CurrentStateVersion}
	}
	for _, name := range stopped {
		found := false
		for i, q := range curState.QuarantinedServices {
			if q.Name == name {
				found = true
				// The user restarted it after NetRiser gave up and it failed
				// again: this is a new incident with a fresh restart budget.
				if q.GaveUp {
					curState.QuarantinedServices[i] = ServiceQuarantineRecord{Name: name, QuarantinedAt: w.clock.Now(), InitialState: "active", NextRetryAfter: w.clock.Now().Add(5 * time.Minute), Enforced: w.keepStopped(name)}
				}
				break
			}
		}
		if !found {
			curState.QuarantinedServices = append(curState.QuarantinedServices, ServiceQuarantineRecord{
				Name:           name,
				QuarantinedAt:  w.clock.Now(),
				InitialState:   "active",
				NextRetryAfter: w.clock.Now().Add(5 * time.Minute),
				Enforced:       w.keepStopped(name),
			})
		}
	}
	_ = w.stateMgr.SaveState(curState)
}

func (w *Watchdog) restartNetwork(ctx context.Context, b netengine.Baseline) netengine.ActionResult {
	act := netengine.ActionResult{Type: netengine.ActionRestartStack, Target: b.Interface, Status: netengine.ActionExecuted, Description: "Reconfigured physical network and restored routes"}
	if err := w.engine.RestartNetworkStack(ctx, b); err != nil {
		act.Status = netengine.ActionFailed
		act.Error = err.Error()
		act.Description = "Physical network recovery did not complete"
	}
	return act
}

// Failure counts must not make reboot faster when the recovery cadence changes.
// Unknown legacy outage start times require a fresh measured outage window.
func (w *Watchdog) guardRebootOutage(state *WatchdogState, allowed bool, reason string) (bool, string) {
	if state != nil && state.RebootedInOutage {
		return false, "already rebooted during this outage; one reboot per outage"
	}
	minimum := time.Duration(w.cfg.RebootMinOutageSec) * time.Second
	if minimum > 0 && (state == nil || state.FirstFailedAt.IsZero() || w.clock.Now().Sub(state.FirstFailedAt) < minimum) {
		return false, fmt.Sprintf("continuous outage shorter than reboot_min_outage_sec (%ds)", w.cfg.RebootMinOutageSec)
	}
	return allowed, reason
}

// ConfigPath returns the explicit path for helpers; empty selects OS defaults.
func (w *Watchdog) ConfigPath() string { return w.configPath }

type StatusReport struct {
	ConfigFile            string                    `json:"config_file"`
	Baseline              netengine.Baseline        `json:"baseline"`
	PolicyRoutingTable    int                       `json:"policy_routing_table"`
	PolicyRoutingPriority int                       `json:"policy_routing_priority"`
	AutoUpdate            bool                      `json:"auto_update"`
	AutoUpdateIntervalSec int                       `json:"auto_update_interval_sec"`
	CheckIntervalSec      int                       `json:"check_interval_sec"`
	RecoveryIntervalSec   int                       `json:"recovery_interval_sec"`
	RebootMinOutageSec    int                       `json:"reboot_min_outage_sec"`
	EnableReboot          bool                      `json:"enable_reboot"`
	DefaultRoutePolicy    string                    `json:"default_route_policy"`
	RebootBudget24h       int                       `json:"reboot_budget_24h"`
	RecentReboots24h      int                       `json:"recent_reboots_24h"`
	RecoveryPaused        bool                      `json:"recovery_paused,omitempty"`
	ProbesBlocked         bool                      `json:"probes_blocked,omitempty"`
	AccessChecked         bool                      `json:"access_checked,omitempty"`
	AccessOK              bool                      `json:"access_ok,omitempty"`
	ObservationMode       bool                      `json:"observation_mode"`
	ConsecutiveFailures   int                       `json:"consecutive_failures"`
	QuarantinedServices   []ServiceQuarantineRecord `json:"quarantined_services"`
	CanaryResults         canary.HealthResult       `json:"canary_results"`
	Errors                []string                  `json:"errors,omitempty"`
}

func (w *Watchdog) StatusReport(ctx context.Context) (*StatusReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var errs []string

	baseline, bErr := w.engine.DetectBaseline(ctx)
	if bErr != nil {
		errs = append(errs, fmt.Sprintf("baseline discovery warning: %v", bErr))
	}

	state, sErr := w.stateMgr.LoadStateReadOnly()
	if sErr != nil {
		errs = append(errs, fmt.Sprintf("state loading warning: %v", sErr))
	}

	fails := 0
	var quarantined []ServiceQuarantineRecord
	if state != nil {
		fails = state.FailCount
		quarantined = state.QuarantinedServices
	}

	canaryRes := w.checker.CheckDetailed(ctx)

	cfgPath := w.configPath
	if cfgPath == "" {
		cfgPath = config.DefaultConfigPath()
	}

	recentReboots := 0
	if w.rebootTracker != nil {
		history, _ := w.rebootTracker.LoadHistory()
		cutoff := w.clock.Now().Add(-24 * time.Hour)
		for _, t := range history {
			if t.After(cutoff) {
				recentReboots++
			}
		}
	}

	report := &StatusReport{
		ConfigFile:            cfgPath,
		Baseline:              baseline,
		PolicyRoutingTable:    w.cfg.PolicyRoutingTable,
		PolicyRoutingPriority: w.cfg.PolicyRoutingPriority,
		EnableReboot:          w.cfg.EnableReboot,
		AutoUpdate:            w.cfg.AutoUpdate,
		AutoUpdateIntervalSec: w.cfg.AutoUpdateIntervalSec,
		DefaultRoutePolicy:    config.DefaultRoutePolicy(w.cfg),
		CheckIntervalSec:      w.cfg.CheckIntervalSec,
		RecoveryIntervalSec:   w.cfg.RecoveryIntervalSec,
		RebootMinOutageSec:    w.cfg.RebootMinOutageSec,
		RebootBudget24h:       w.cfg.RebootBudgetCount,
		RecentReboots24h:      recentReboots,
		ObservationMode:       w.cfg.ObservationMode,
		ConsecutiveFailures:   fails,
		RecoveryPaused:        state != nil && state.RecoveryPaused,
		ProbesBlocked:         state != nil && state.ProbesBlocked,
		AccessChecked:         canaryRes.AccessChecked,
		AccessOK:              canaryRes.MeshHealthy,
		QuarantinedServices:   quarantined,
		CanaryResults:         canaryRes,
		Errors:                errs,
	}
	return report, nil
}

func (w *Watchdog) StatusJSON(ctx context.Context) (string, error) {
	rep, err := w.StatusReport(ctx)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (w *Watchdog) Status(ctx context.Context) string {
	rep, _ := w.StatusReport(ctx)
	if rep == nil {
		return "Error generating status report\n"
	}

	var buf bytes.Buffer
	buf.WriteString("======================================================================\n")
	buf.WriteString("                NETRISER STATUS REPORT                   \n")
	buf.WriteString("======================================================================\n")
	buf.WriteString(fmt.Sprintf("Configuration File:   %s\n", rep.ConfigFile))
	buf.WriteString(fmt.Sprintf("Observation Mode:     %t\n", rep.ObservationMode))
	buf.WriteString(fmt.Sprintf("Physical Interface:   %s\n", rep.Baseline.Interface))
	buf.WriteString(fmt.Sprintf("Physical IP Address:  %s\n", rep.Baseline.IP))
	buf.WriteString(fmt.Sprintf("Physical Gateway:     %s\n", rep.Baseline.Gateway))
	buf.WriteString(fmt.Sprintf("Policy Routing Table: %d\n", rep.PolicyRoutingTable))
	buf.WriteString(fmt.Sprintf("Policy Rule Priority: %d\n", rep.PolicyRoutingPriority))
	buf.WriteString(fmt.Sprintf("Automatic Updates:    %t (every %ds)\n", rep.AutoUpdate, rep.AutoUpdateIntervalSec))
	buf.WriteString(fmt.Sprintf("Default Route:        %s\n", rep.DefaultRoutePolicy))
	if rep.EnableReboot {
		buf.WriteString("Emergency Reboot:     true (one per outage)\n")
	} else {
		buf.WriteString("Emergency Reboot:     false\n")
	}
	buf.WriteString(fmt.Sprintf("Consecutive Failures: %d\n", rep.ConsecutiveFailures))
	if rep.AccessChecked {
		if rep.AccessOK {
			buf.WriteString("Remote Access:        ok (an access address answers)\n")
		} else {
			buf.WriteString("Remote Access:        LOST (no access address answers)\n")
		}
	}
	if rep.RecoveryPaused {
		buf.WriteString("Recovery Paused:      yes (no connectivity after the emergency reboot; only checking)\n")
	}
	if rep.ProbesBlocked {
		buf.WriteString("Internet Probes:      look BLOCKED (system DNS and the router answer); no network restart or reboot. Change canary_targets with `nr setup`\n")
	}

	if len(rep.QuarantinedServices) > 0 {
		var list []string
		for _, q := range rep.QuarantinedServices {
			if q.Enforced {
				list = append(list, fmt.Sprintf("%s (stopped: took over the default route on a host without a full tunnel; not restarted)", q.Name))
			} else if q.GaveUp {
				list = append(list, fmt.Sprintf("%s (left stopped after %d failed restarts; start it yourself)", q.Name, q.Attempts))
			} else {
				list = append(list, fmt.Sprintf("%s (retry in %v)", q.Name, time.Until(q.NextRetryAfter).Round(time.Second)))
			}
		}
		buf.WriteString(fmt.Sprintf("Quarantined Services: %s\n", strings.Join(list, ", ")))
	} else {
		buf.WriteString("Quarantined Services: [None]\n")
	}

	if len(rep.Errors) > 0 {
		buf.WriteString(fmt.Sprintf("Diagnostics Warnings: %s\n", strings.Join(rep.Errors, "; ")))
	}

	buf.WriteString("\n--- Canary Probes Status ---\n")
	for _, det := range rep.CanaryResults.Details {
		status := "FAIL"
		if det.Success {
			status = "OK"
		}
		errMsg := ""
		if det.Error != nil {
			errMsg = fmt.Sprintf(" (%v)", det.Error)
		}
		buf.WriteString(fmt.Sprintf("  [%s] %-22s latency=%-8v%s\n", status, det.Target, det.Latency.Round(time.Millisecond), errMsg))
	}
	buf.WriteString(fmt.Sprintf("Overall Health:       %s\n", rep.CanaryResults.SummaryString()))
	buf.WriteString("======================================================================\n")

	return buf.String()
}

type DiagnosticReport struct {
	Timestamp time.Time          `json:"timestamp"`
	Baseline  netengine.Baseline `json:"baseline"`
	Dump      string             `json:"dump"`
}

func (w *Watchdog) DiagnoseJSON(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	baseline, _ := w.engine.DetectBaseline(ctx)
	dump, err := w.engine.DumpDiagnostics(ctx, baseline)
	if err != nil {
		return "", err
	}
	rep := DiagnosticReport{
		Timestamp: w.clock.Now(),
		Baseline:  baseline,
		Dump:      dump,
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type DryRunReport struct {
	Timestamp          time.Time          `json:"timestamp"`
	Healthy            bool               `json:"healthy"`
	CurrentFailCount   int                `json:"current_fail_count"`
	ProjectedFailCount int                `json:"projected_fail_count"`
	Baseline           netengine.Baseline `json:"baseline"`
	BaselineValid      bool               `json:"baseline_valid"`
	EscalationStage    int                `json:"escalation_stage"`
	ActionAllowed      bool               `json:"action_allowed"`
	Reason             string             `json:"reason"`
	PlannedActions     []string           `json:"planned_actions"`
}

func (w *Watchdog) EvaluateDryRun(ctx context.Context) (*DryRunReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	baseline, baselineErr := w.engine.DetectBaseline(ctx)
	state, _ := w.stateMgr.LoadStateReadOnly()
	fails := 0
	if state != nil {
		fails = state.FailCount
	}

	canaryRes := w.checker.CheckFast(ctx)
	report := &DryRunReport{
		Timestamp:          w.clock.Now(),
		Healthy:            canaryRes.Healthy,
		CurrentFailCount:   fails,
		ProjectedFailCount: fails,
		Baseline:           baseline,
		BaselineValid:      baselineErr == nil && baseline.IsValid(),
	}

	if canaryRes.Healthy {
		report.EscalationStage = 0
		report.ActionAllowed = true
		report.Reason = "Canary connectivity healthy; no remediation needed"
		report.PlannedActions = []string{"None (network healthy)"}
		return report, nil
	}
	if canaryRes.DNSOnlyFailure() {
		_, supported := w.engine.(netengine.DNSRecoveryEngine)
		report.ActionAllowed = supported && w.cfg.AllowDNSRecovery && !w.cfg.ObservationMode
		report.Reason = "System DNS failed while IP connectivity is healthy; DNS-only recovery, no reboot escalation"
		if !w.cfg.ObservationMode {
			report.ProjectedFailCount = 0
		}
		if report.ActionAllowed {
			report.PlannedActions = []string{"Restore last healthy system DNS configuration and its resolver service; verify name resolution"}
		} else {
			report.PlannedActions = []string{"Skip DNS recovery (disabled, observation mode, or unsupported platform)"}
		}
		return report, nil
	}

	projectedFails := fails + 1
	report.ProjectedFailCount = projectedFails

	inStartupGrace := false
	if w.cfg.StartupGraceSec > 0 {
		startupGraceDuration := time.Duration(w.cfg.StartupGraceSec) * time.Second
		if w.clock.Now().Sub(w.startedAt) < startupGraceDuration {
			inStartupGrace = true
		}
	}
	rebootWindow := time.Duration(w.cfg.RebootBudgetWindowSec) * time.Second
	rebootAllowed, budgetReason := w.rebootTracker.CanReboot(w.cfg.RebootBudgetCount, rebootWindow)
	rebootAllowed, budgetReason = w.guardRebootOutage(state, rebootAllowed, budgetReason)

	actionBaseline := baseline
	if baselineErr != nil {
		actionBaseline.IP = ""
	}
	decision := DecideEscalation(projectedFails, w.cfg, actionBaseline, rebootAllowed, budgetReason, inStartupGrace)
	report.EscalationStage = decision.Stage
	report.ActionAllowed = decision.ActionAllowed
	report.Reason = decision.Reason
	if decision.SkipReason != "" {
		report.Reason = decision.SkipReason
	}
	if decision.Stage >= 3 {
		if blocked, why := w.probesBlocked(ctx, canaryRes, baseline); blocked {
			report.ActionAllowed = false
			report.Reason = "internet probes look blocked: " + why
			report.PlannedActions = []string{"Log only: no network restart or reboot while the probes look blocked; change canary_targets"}
			return report, nil
		}
	}

	switch decision.Stage {
	case 4:
		if decision.ActionAllowed {
			report.PlannedActions = append(report.PlannedActions, "Execute emergency host reboot")
		} else {
			report.PlannedActions = append(report.PlannedActions, fmt.Sprintf("Skip reboot (%s); fallback to network restart & route sanitation", decision.SkipReason))
		}
	case 3:
		if decision.ActionAllowed {
			report.PlannedActions = append(report.PlannedActions, fmt.Sprintf("Restart network stack on %s", baseline.Interface))
		} else {
			report.PlannedActions = append(report.PlannedActions, fmt.Sprintf("Skip network restart (%s)", decision.SkipReason))
		}
		if w.cfg.AllowRouteSanitation && baselineErr == nil && baseline.IsValid() {
			report.PlannedActions = append(report.PlannedActions, "Surgically clean rogue routes")
		}
	case 2:
		if decision.ActionAllowed {
			report.PlannedActions = append(report.PlannedActions, fmt.Sprintf("Quarantine the service of an overlay that publishes a rogue route (eligible: %s)", strings.Join(w.cfg.MonitoredServices, ", ")))
		} else {
			report.PlannedActions = append(report.PlannedActions, fmt.Sprintf("Skip quarantine (%s)", decision.SkipReason))
		}
		if w.cfg.AllowRouteSanitation && baselineErr == nil && baseline.IsValid() {
			report.PlannedActions = append(report.PlannedActions, "Surgically clean rogue routes")
		}
	case 1:
		if decision.ActionAllowed {
			report.PlannedActions = append(report.PlannedActions, "Surgically remove rogue default and /1 routes")
		} else {
			report.PlannedActions = append(report.PlannedActions, fmt.Sprintf("Skip route sanitation (%s)", decision.SkipReason))
		}
	default:
		report.PlannedActions = append(report.PlannedActions, "Observation mode: log only, no actions taken")
	}

	return report, nil
}

type ConfigValidationReport struct {
	Valid      bool               `json:"valid"`
	ConfigFile string             `json:"config_file"`
	Baseline   netengine.Baseline `json:"baseline"`
	Errors     []string           `json:"errors,omitempty"`
	Warnings   []string           `json:"warnings,omitempty"`
}

func (w *Watchdog) ValidateConfiguration(ctx context.Context) *ConfigValidationReport {
	if ctx == nil {
		ctx = context.Background()
	}
	cfgPath := w.configPath
	if cfgPath == "" {
		cfgPath = config.DefaultConfigPath()
	}

	rep := &ConfigValidationReport{
		Valid:      true,
		ConfigFile: cfgPath,
	}

	if err := w.cfg.Validate(); err != nil {
		rep.Valid = false
		rep.Errors = append(rep.Errors, err.Error())
	}

	baseline, err := w.engine.DetectBaseline(ctx)
	rep.Baseline = baseline
	if err != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("baseline discovery warning: %v", err))
	} else if !baseline.IsValid() {
		rep.Warnings = append(rep.Warnings, "physical interface or default gateway not yet detected")
	}

	return rep
}

func (w *Watchdog) Reset() {
	lock, err := AcquireLock(w.cfg.LockFile)
	if err == nil {
		defer lock.Unlock()
	}
	_ = w.writeFailCount(0)
	w.logger.Info("Watchdog failure count reset to 0 (quarantine history preserved).")
}

func (w *Watchdog) RestoreQuarantined(ctx context.Context) error {
	lock, err := AcquireLock(w.cfg.LockFile)
	if err != nil {
		return err
	}
	defer lock.Unlock()

	state, err := w.stateMgr.LoadState()
	if err != nil || state == nil || len(state.QuarantinedServices) == 0 {
		w.logger.Info("No quarantined services to restore.")
		return nil
	}

	var names []string
	for _, q := range state.QuarantinedServices {
		names = append(names, q.Name)
	}
	_, rErr := w.engine.RestoreMeshServices(ctx, names)
	state.QuarantinedServices = nil
	_ = w.stateMgr.SaveState(state)
	return rErr
}

func (w *Watchdog) ApplyPolicy(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	lock, err := AcquireLock(w.cfg.LockFile)
	if err != nil {
		return err
	}
	defer lock.Unlock()

	// Boot-time retry loop: wait for physical interface to obtain an IP address if not available yet
	var baseline netengine.Baseline
	deadline := w.clock.Now().Add(30 * time.Second)
	for {
		baseline, err = w.engine.DetectBaseline(ctx)
		if err == nil && baseline.IP != "" {
			break
		}
		if !w.clock.Now().Before(deadline) || ctx.Err() != nil {
			if err != nil {
				return fmt.Errorf("baseline detection failed: %w", err)
			}
			return fmt.Errorf("baseline interface %q has no IP address assigned after timeout", baseline.Interface)
		}
		if sleepErr := w.clock.Sleep(ctx, 1*time.Second); sleepErr != nil {
			return sleepErr
		}
	}

	return w.engine.ApplyPolicyRouting(ctx, baseline)
}

func (w *Watchdog) RemovePolicy(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	lock, err := AcquireLock(w.cfg.LockFile)
	if err != nil {
		return err
	}
	defer lock.Unlock()

	baseline, _ := w.engine.DetectBaseline(ctx)
	return w.engine.RemovePolicyRouting(ctx, baseline)
}

func (w *Watchdog) Diagnose(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	baseline, _ := w.engine.DetectBaseline(ctx)
	return w.engine.DumpDiagnostics(ctx, baseline)
}

func (w *Watchdog) SimulateHijack(ctx context.Context, duration time.Duration) (func(), error) {
	session, err := w.SimulateHijackSession(ctx, duration)
	if err != nil {
		return nil, err
	}
	return func() {
		_ = session.Disarm()
	}, nil
}

func (w *Watchdog) SimulateHijackSession(ctx context.Context, duration time.Duration) (netengine.SimulationSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	baseline, err := w.engine.DetectBaseline(ctx)
	if err != nil {
		return nil, err
	}
	// Never allow reboot in simulation
	w.cfg.EnableReboot = false

	return w.engine.SimulateHijackSession(ctx, baseline, duration)
}
