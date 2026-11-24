package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/netengine"
)

// Local block recovery: see netengine/blockers.go.

const (
	// localBlockChecks consecutive failed self-connections before acting.
	localBlockChecks = 2
	// knownGoodMargin: components first seen less than this before the block
	// started are not trusted; they may have been installed just before it.
	knownGoodMargin = time.Hour
	// snapshotRefresh is how often the working-state snapshot is updated.
	snapshotRefresh = time.Hour
	// selfConnectTimeout limits each connection to the host's own port.
	selfConnectTimeout = 3 * time.Second
	// localCheckHealthyEvery: while the internet checks pass, the host's own
	// ports are tested this often rather than in every check, to keep SSH
	// and RDP logs quiet. During an outage, or once a block was seen, every
	// check tests them.
	localCheckHealthyEvery = 5 * time.Minute
)

// SetDialer replaces the function used to connect to the host's own ports.
func (w *Watchdog) SetDialer(d netengine.DialFunc) { w.dial = d }

func (w *Watchdog) blockerEngine() (netengine.BlockerEngine, bool) {
	be, ok := w.engine.(netengine.BlockerEngine)
	return be, ok && len(w.cfg.AccessPorts) > 0
}

// localAccess connects from the host to its own listening access ports.
// On Linux and macOS the engine sends the connections over a virtual
// Ethernet pair (netengine.LocalProber) and a failing port counts only if
// it passed before (okPorts).
func (w *Watchdog) localAccess(ctx context.Context, be netengine.BlockerEngine, ip string, okPorts []int) netengine.LocalAccessResult {
	listening, err := be.ListeningPorts(ctx)
	if err != nil {
		return netengine.LocalAccessResult{Address: ip}
	}
	prober, ok := be.(netengine.LocalProber)
	if !ok || w.dial != nil {
		return netengine.TestLocalAccess(ctx, ip, w.cfg.AccessPorts, listening, selfConnectTimeout, w.dial)
	}
	res := netengine.LocalAccessResult{Address: ip}
	var ports []int
	for _, p := range w.cfg.AccessPorts {
		if netengine.ListensOn(listening[p], ip) {
			ports = append(ports, p)
		}
	}
	probes, err := prober.ProbeLocal(ctx, ip, ports, selfConnectTimeout)
	if err != nil {
		// Logged once per distinct error, not every check.
		if msg := err.Error(); msg != w.probeErr {
			w.probeErr = msg
			w.logger.Warn("Local access check unavailable: the self-probe over a temporary virtual interface failed: %v", err)
		}
		return res
	}
	for _, p := range probes {
		if !p.OK && !slices.Contains(okPorts, p.Port) {
			res.Unproven = append(res.Unproven, p)
			continue
		}
		res.Probes = append(res.Probes, p)
	}
	return res
}

// needsHistory reports whether failing ports count only after passing once.
func needsHistory(be netengine.BlockerEngine) bool {
	_, ok := be.(netengine.LocalProber)
	return ok
}

// checkLocalBlock runs in every check. When the host cannot connect to its
// own listening access ports in localBlockChecks checks in a row, it disables
// the services and drivers that appeared since the host last worked. It
// reports whether that restored access, which ends the check cycle.
func (w *Watchdog) checkLocalBlock(ctx context.Context, baseline netengine.Baseline, healthy bool, report *CheckReport) bool {
	be, ok := w.blockerEngine()
	if !ok || !w.cfg.LocalBlockRecovery {
		return false
	}
	state, _ := w.stateMgr.LoadState()
	if state == nil {
		state = &WatchdogState{Version: CurrentStateVersion}
	}
	now := w.clock.Now()
	if healthy && state.LocalBlockCount == 0 && !w.lastLocalCheck.IsZero() &&
		now.Sub(w.lastLocalCheck) < localCheckHealthyEvery && !now.Before(w.lastLocalCheck) {
		return false
	}
	w.lastLocalCheck = now
	res := w.localAccess(ctx, be, baseline.IP, state.LocalPortsOK)
	if needsHistory(be) {
		added := false
		for _, p := range res.Probes {
			if p.OK && !slices.Contains(state.LocalPortsOK, p.Port) {
				state.LocalPortsOK = append(state.LocalPortsOK, p.Port)
				added = true
			}
		}
		if added {
			_ = w.stateMgr.SaveState(state)
		}
	}
	if !res.Blocked() {
		if state.LocalBlockCount > 0 || state.LocalBlockActed {
			w.logger.Info("Local access restored: this host accepts connections to its own ports again (%s).", res.Summary())
			state.LocalBlockCount, state.LocalBlockSince, state.LocalBlockActed = 0, time.Time{}, false
			_ = w.stateMgr.SaveState(state)
		}
		if healthy && res.Tested() {
			w.refreshSnapshot(ctx, be)
		}
		return false
	}

	report.LocalBlocked = true
	state.LocalBlockCount++
	if state.LocalBlockCount == 1 {
		state.LocalBlockSince = w.clock.Now()
		w.logger.Warn("Local access check FAILED: this host cannot connect to its own listening port(s) on %s (%s). Something on the host itself is blocking connections, for example a firewall driver.", res.Address, res.Summary())
	}
	act := state.LocalBlockCount >= localBlockChecks && !state.LocalBlockActed
	if act {
		state.LocalBlockActed = true
	}
	if err := w.stateMgr.SaveState(state); err != nil || !act {
		return false
	}

	blockers, snapTime, err := w.findBlockers(ctx, be, state.LocalBlockSince)
	if err != nil {
		w.logger.Warn("Local block: the services and drivers could not be examined: %v. Recording only.", err)
		return false
	}
	if len(blockers) == 0 {
		if snapTime.IsZero() || w.cfg.LocalBlockUntrustedDrivers {
			w.logger.Warn("Local block: nothing (service, driver, firewall rules) is new since this host last worked (%s), and no loaded driver or kernel module lacks a trusted signature. Nothing was disabled; restarting will not help if the cause loads again at startup.", snapshotLabel(snapTime))
		} else {
			w.logger.Warn("Local block: nothing (service, driver, firewall rules) is new since this host last worked (%s). Drivers and kernel modules without a trusted signature were not checked (local_block_untrusted_drivers: false). Nothing was disabled; restarting will not help if the cause loads again at startup.", snapshotLabel(snapTime))
		}
		return false
	}
	if w.cfg.ObservationMode {
		w.logger.Warn("[Observation] Local block: NetRiser would disable %s.", describeBlockers(blockers))
		return false
	}

	w.logger.Recovery("Local block: disabling %s.", describeBlockers(blockers))
	actions := w.DisableBlockers(ctx, blockers)
	report.ActionsTaken = append(report.ActionsTaken, actions...)

	if err := w.clock.Sleep(ctx, 3*time.Second); err != nil {
		return false
	}
	after := w.localAccess(ctx, be, baseline.IP, state.LocalPortsOK)
	if !after.Blocked() {
		w.logger.Recovery("Local access RESTORED by disabling %s (%s). Undo: nr blockers restore all", blockerNames(blockers), after.Summary())
		report.Remediated = true
		if fresh, _ := w.stateMgr.LoadState(); fresh != nil {
			fresh.LocalBlockCount, fresh.LocalBlockSince, fresh.LocalBlockActed = 0, time.Time{}, false
			_ = w.stateMgr.SaveState(fresh)
		}
		return true
	}
	w.rebootForBlockers(ctx, report)
	return false
}

// restartCommand is how the user restarts this system.
func restartCommand() string {
	if runtime.GOOS == "windows" {
		return "shutdown /r /t 0"
	}
	return "sudo shutdown -r now"
}

// rebootForBlockers restarts the host when disabled drivers stay loaded,
// within the emergency reboot rules (enable_reboot, budget, one per outage).
func (w *Watchdog) rebootForBlockers(ctx context.Context, report *CheckReport) {
	state, _ := w.stateMgr.LoadState()
	if state == nil {
		state = &WatchdogState{Version: CurrentStateVersion}
	}
	allowed, reason := w.rebootTracker.CanReboot(w.cfg.RebootBudgetCount, time.Duration(w.cfg.RebootBudgetWindowSec)*time.Second)
	switch {
	case !w.cfg.EnableReboot:
		allowed, reason = false, "emergency reboot is off (nr reboot on)"
	case state.RebootedInOutage:
		allowed, reason = false, "already rebooted during this outage"
	}
	if !allowed {
		w.logger.Warn("Local block remains: the disabled components are still loaded. Restarting completes the fix (%s): %s", reason, restartCommand())
		report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{Type: netengine.ActionReboot, Target: "host", Status: netengine.ActionSkipped,
			Description: "Restart to unload the disabled components skipped: " + reason})
		return
	}
	w.logger.Recovery("Local block remains: the disabled components are still loaded. Restarting the host to unload them; they stay disabled.")
	_ = w.rebootTracker.RecordReboot()
	state.RebootedInOutage = true
	if err := w.stateMgr.SaveState(state); err != nil {
		w.logger.Error("Could not record the reboot in state (%v); not restarting.", err)
		return
	}
	report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{Type: netengine.ActionReboot, Target: "host", Status: netengine.ActionExecuted,
		Description: "Restarted the host to unload the disabled components"})
	_ = w.engine.EmergencyReboot(ctx, "unload components that block connections on this host")
}

// protectedComponents is the built-in list, the VPN and overlay services
// NetRiser knows, monitored_services and protected_components.
func (w *Watchdog) protectedComponents() []string {
	out := append([]string{}, netengine.DefaultProtectedComponents...)
	add := func(names []string) {
		for _, n := range names {
			n = strings.NewReplacer("${iface}", "*", "{iface}", "*").Replace(n)
			if n != "" && n != "*" {
				out = append(out, n)
			}
		}
	}
	if runtime.GOOS != "windows" {
		out = append(out, netengine.DefaultProtectedUnixComponents...)
	}
	for _, o := range netengine.BuiltinOverlays() {
		add(o.WindowsServices)
		add(o.LinuxServices)
	}
	for _, o := range w.cfg.Overlays {
		add(o.Services)
	}
	add(w.cfg.MonitoredServices)
	add(w.cfg.ProtectedComponents)
	return out
}

// findBlockers chooses the components to disable for a block that started
// at since. It returns the time of the working-state snapshot used. When the
// snapshot shows nothing new and local_block_untrusted_drivers is on, the
// rule used without a snapshot applies: a component that worked for hours
// may still be a test build that began blocking later.
func (w *Watchdog) findBlockers(ctx context.Context, be netengine.BlockerEngine, since time.Time) ([]netengine.Blocker, time.Time, error) {
	comps, err := be.Components(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	snap := w.loadSnapshot()
	var snapTime time.Time
	if snap != nil {
		snapTime = snap.TakenAt
	}
	if since.IsZero() {
		since = w.clock.Now()
	}
	policy := netengine.BlockerPolicy{Snapshot: snap, KnownGoodBefore: since.Add(-knownGoodMargin), Protected: w.protectedComponents()}
	sigs := map[string]netengine.Signature{}
	blockers, err := selectBlockers(ctx, be, comps, policy, sigs)
	if err == nil && len(blockers) == 0 && snap != nil && w.cfg.LocalBlockUntrustedDrivers {
		policy.Snapshot = nil
		blockers, err = selectBlockers(ctx, be, comps, policy, sigs)
	}
	return blockers, snapTime, err
}

// selectBlockers checks the signatures SelectBlockers needs (caching them in
// sigs) and returns its choice.
func selectBlockers(ctx context.Context, be netengine.BlockerEngine, comps []netengine.Component, policy netengine.BlockerPolicy, sigs map[string]netengine.Signature) ([]netengine.Blocker, error) {
	check := func(cs []netengine.Component) error {
		var need []netengine.Component
		for _, c := range cs {
			if _, ok := sigs[strings.ToLower(c.Name)]; !ok {
				need = append(need, c)
			}
		}
		if len(need) == 0 {
			return nil
		}
		more, err := be.Signatures(ctx, need)
		for k, v := range more {
			sigs[k] = v
		}
		return err
	}
	if err := check(netengine.BlockerCandidates(comps, policy)); err != nil {
		return nil, err
	}
	blockers := netengine.SelectBlockers(comps, sigs, policy)
	// Services added because they start a chosen driver: check them too, so
	// a Windows service is never disabled.
	var added []netengine.Component
	for _, b := range blockers {
		if _, ok := sigs[strings.ToLower(b.Name)]; !ok {
			added = append(added, b.Component)
		}
	}
	if len(added) > 0 {
		if err := check(added); err != nil {
			return nil, err
		}
		blockers = netengine.SelectBlockers(comps, sigs, policy)
	}
	return blockers, nil
}

// DisableBlockers disables the given components and records them for undo.
func (w *Watchdog) DisableBlockers(ctx context.Context, blockers []netengine.Blocker) []netengine.ActionResult {
	be, ok := w.engine.(netengine.BlockerEngine)
	if !ok {
		return nil
	}
	var actions []netengine.ActionResult
	var done []DisabledComponent
	for _, b := range blockers {
		a := be.DisableComponent(ctx, b)
		w.logger.Recovery("  - %s", a.String())
		actions = append(actions, a)
		if a.Status == netengine.ActionExecuted || a.Status == netengine.ActionPartial {
			done = append(done, DisabledComponent{Name: b.Name, PreviousStart: b.Start, Kernel: b.Kernel, Image: b.Image, Reason: b.Reason, DisabledAt: w.clock.Now()})
		}
	}
	if len(done) == 0 {
		return actions
	}
	state, _ := w.stateMgr.LoadState()
	if state == nil {
		state = &WatchdogState{Version: CurrentStateVersion}
	}
	for _, d := range done {
		known := false
		for _, old := range state.DisabledComponents {
			if strings.EqualFold(old.Name, d.Name) {
				known = true
				break
			}
		}
		if !known {
			state.DisabledComponents = append(state.DisabledComponents, d)
		}
	}
	if err := w.stateMgr.SaveState(state); err != nil {
		w.logger.Error("Could not record the disabled components (%v); restore them with: sc config <name> start= demand", err)
	}
	return actions
}

// RestoreBlockers sets disabled components back to their previous start
// type; all of them when names is empty. They start at the next restart of
// Windows (or with sc start).
func (w *Watchdog) RestoreBlockers(ctx context.Context, names []string) ([]netengine.ActionResult, error) {
	be, ok := w.engine.(netengine.BlockerEngine)
	if !ok {
		return nil, fmt.Errorf("not supported on this system")
	}
	state, err := w.stateMgr.LoadState()
	if err != nil || state == nil {
		return nil, fmt.Errorf("state not available: %v", err)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	var actions []netengine.ActionResult
	var keep []DisabledComponent
	for _, d := range state.DisabledComponents {
		if len(want) > 0 && !want[strings.ToLower(d.Name)] {
			keep = append(keep, d)
			continue
		}
		delete(want, strings.ToLower(d.Name))
		a := be.RestoreComponent(ctx, d.Name, d.PreviousStart)
		actions = append(actions, a)
		if a.Status != netengine.ActionExecuted {
			keep = append(keep, d)
		} else {
			if runtime.GOOS == "windows" {
				w.logger.Info("Restored %s to %s start (nr blockers restore).", d.Name, netengine.StartName(d.PreviousStart))
			} else {
				w.logger.Info("Restored %s (nr blockers restore): %s", d.Name, a.Description)
			}
		}
	}
	state.DisabledComponents = keep
	if err := w.stateMgr.SaveState(state); err != nil {
		return actions, err
	}
	if len(want) > 0 {
		var missing []string
		for n := range want {
			missing = append(missing, n)
		}
		return actions, fmt.Errorf("not disabled by NetRiser: %s", strings.Join(missing, ", "))
	}
	return actions, nil
}

// BlockerScan is the read-only view behind `nr blockers`.
type BlockerScan struct {
	Supported  bool                        `json:"supported"`
	Access     netengine.LocalAccessResult `json:"local_access"`
	Snapshot   time.Time                   `json:"snapshot,omitempty"`
	Candidates []netengine.Blocker         `json:"would_disable"`
	Disabled   []DisabledComponent         `json:"disabled"`
	Enabled    bool                        `json:"local_block_recovery"`
	Untrusted  bool                        `json:"local_block_untrusted_drivers"`
}

// ScanBlockers tests local access and lists what recovery would disable now,
// without changing anything.
func (w *Watchdog) ScanBlockers(ctx context.Context) (*BlockerScan, error) {
	scan := &BlockerScan{Enabled: w.cfg.LocalBlockRecovery, Untrusted: w.cfg.LocalBlockUntrustedDrivers}
	if state, _ := w.stateMgr.LoadStateReadOnly(); state != nil {
		scan.Disabled = state.DisabledComponents
	}
	be, ok := w.engine.(netengine.BlockerEngine)
	if !ok {
		return scan, nil
	}
	scan.Supported = true
	baseline, _ := w.engine.DetectBaseline(ctx)
	var okPorts []int
	if state, _ := w.stateMgr.LoadStateReadOnly(); state != nil {
		okPorts = state.LocalPortsOK
	}
	scan.Access = w.localAccess(ctx, be, baseline.IP, okPorts)
	since := w.clock.Now()
	if state, _ := w.stateMgr.LoadStateReadOnly(); state != nil && !state.LocalBlockSince.IsZero() {
		since = state.LocalBlockSince
	}
	blockers, snapTime, err := w.findBlockers(ctx, be, since)
	scan.Snapshot = snapTime
	scan.Candidates = blockers
	return scan, err
}

// --- working-state snapshot --------------------------------------------------

func (w *Watchdog) snapshotPath() string {
	return filepath.Join(w.cfg.StateDir, "components.json")
}

func (w *Watchdog) loadSnapshot() *netengine.ComponentSnapshot {
	data, err := os.ReadFile(w.snapshotPath())
	if err != nil {
		return nil
	}
	var s netengine.ComponentSnapshot
	if json.Unmarshal(data, &s) != nil || s.Components == nil {
		return nil
	}
	return &s
}

// refreshSnapshot records the components of a working host, at most once
// per snapshotRefresh.
func (w *Watchdog) refreshSnapshot(ctx context.Context, be netengine.BlockerEngine) {
	snap := w.loadSnapshot()
	now := w.clock.Now()
	if snap != nil && now.Sub(snap.TakenAt) < snapshotRefresh && !snap.TakenAt.After(now) {
		return
	}
	comps, err := be.Components(ctx)
	if err != nil {
		w.logger.Warn("Working-state snapshot not updated: %v", err)
		return
	}
	if saver, ok := be.(netengine.WorkingStateSaver); ok {
		if err := saver.SaveWorkingState(ctx, now); err != nil {
			w.logger.Warn("Working copies of the firewall rules not saved: %v", err)
		}
	}
	if snap == nil {
		snap = &netengine.ComponentSnapshot{}
	}
	netengine.MergeSnapshot(snap, comps, now)
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	tmp := w.snapshotPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		w.logger.Warn("Working-state snapshot not saved: %v", err)
		return
	}
	if err := os.Rename(tmp, w.snapshotPath()); err != nil {
		w.logger.Warn("Working-state snapshot not saved: %v", err)
	}
}

func snapshotLabel(t time.Time) string {
	if t.IsZero() {
		return "no snapshot of the working state yet"
	}
	return "working-state snapshot from " + t.Local().Format("2006-01-02 15:04")
}

func blockerNames(bs []netengine.Blocker) string {
	var n []string
	for _, b := range bs {
		n = append(n, b.Name)
	}
	return strings.Join(n, ", ")
}

func describeBlockers(bs []netengine.Blocker) string {
	var parts []string
	for _, b := range bs {
		if b.Unix() {
			parts = append(parts, fmt.Sprintf("%s (%s; %s)", b.Name, b.KindLabel(), b.Reason))
			continue
		}
		signer := b.Sig.Signer
		if signer == "" {
			signer = "unsigned"
		}
		parts = append(parts, fmt.Sprintf("%s (%s, %s; %s)", b.Name, b.KindLabel(), signer, b.Reason))
	}
	return strings.Join(parts, "; ")
}
