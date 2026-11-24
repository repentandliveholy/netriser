package watchdog

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/canary"
	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
)

// blockerMockEngine is a Windows-like engine on which RFW holds every new
// connection until its service is disabled.
type blockerMockEngine struct {
	*mockEngine
	comps     []netengine.Component
	sigs      map[string]netengine.Signature
	disabled  []string
	restored  map[string]int
	blocking  bool
	stayStuck bool // the driver stays loaded after disabling
	tests     int  // local access tests run
}

func (m *blockerMockEngine) ListeningPorts(ctx context.Context) (map[int][]string, error) {
	m.tests++
	return map[int][]string{22: {"0.0.0.0"}, 3389: {"0.0.0.0"}}, nil
}

func (m *blockerMockEngine) Components(ctx context.Context) ([]netengine.Component, error) {
	return m.comps, nil
}

func (m *blockerMockEngine) Signatures(ctx context.Context, comps []netengine.Component) (map[string]netengine.Signature, error) {
	out := map[string]netengine.Signature{}
	for _, c := range comps {
		out[strings.ToLower(c.Name)] = m.sigs[strings.ToLower(c.Name)]
	}
	return out, nil
}

func (m *blockerMockEngine) DisableComponent(ctx context.Context, b netengine.Blocker) netengine.ActionResult {
	c := b.Component
	m.disabled = append(m.disabled, c.Name)
	if !m.stayStuck {
		m.blocking = false
	}
	return netengine.ActionResult{Type: netengine.ActionDisableComponent, Target: c.Name, Status: netengine.ActionExecuted}
}

func (m *blockerMockEngine) RestoreComponent(ctx context.Context, name string, start int) netengine.ActionResult {
	if m.restored == nil {
		m.restored = map[string]int{}
	}
	m.restored[name] = start
	return netengine.ActionResult{Type: netengine.ActionRestoreComponent, Target: name, Status: netengine.ActionExecuted}
}

func setupBlockerWatchdog(t *testing.T) (*Watchdog, *config.Config, *blockerMockEngine, *fakeChecker) {
	w, cfg, base, checker := setupTestWatchdog(t)
	engine := &blockerMockEngine{
		mockEngine: base,
		blocking:   true,
		comps: []netengine.Component{
			{Name: "RfwFilter", Kernel: true, Running: true, Start: netengine.StartDemand, Image: `C:\Program Files\rfw\rfwfilter.sys`},
			{Name: "RfwService", Start: netengine.StartAuto, Image: `"C:\Program Files\rfw\rfw-service.exe" run`, DependsOn: []string{"RfwFilter"}},
			{Name: "Tailscale", Start: netengine.StartAuto, Image: `"C:\Program Files\Tailscale\tailscaled.exe"`},
		},
		sigs: map[string]netengine.Signature{
			"rfwfilter":  {Status: "UnknownError", Signer: "RFW Test"},
			"rfwservice": {Status: "NotSigned"},
			"tailscale":  {Valid: true, Signer: "Tailscale Inc.", Status: "Valid"},
		},
	}
	w.SetEngine(engine)
	w.SetDialer(func(ctx context.Context, addr string) error {
		if engine.blocking {
			return context.DeadlineExceeded
		}
		return nil
	})
	// Outbound connections are held too, so the internet probes fail.
	checker.fastResult = canary.HealthResult{Healthy: false}
	return w, cfg, engine, checker
}

func TestLocalBlockDisablesRFWAndRestoresAccess(t *testing.T) {
	w, _, engine, _ := setupBlockerWatchdog(t)

	rep, _ := w.RunCheckCycle(context.Background())
	if !rep.LocalBlocked || len(engine.disabled) != 0 {
		t.Fatalf("acted on the first failed check: %+v, disabled %v", rep, engine.disabled)
	}
	rep, _ = w.RunCheckCycle(context.Background())
	if got := strings.Join(engine.disabled, ","); got != "RfwService,RfwFilter" {
		t.Fatalf("disabled %q, want RfwService,RfwFilter", got)
	}
	if !rep.Remediated || engine.rebootCalled {
		t.Fatalf("access not reported restored, or rebooted needlessly: %+v", rep)
	}
	state, _ := w.stateMgr.LoadState()
	if len(state.DisabledComponents) != 2 || state.DisabledComponents[0].PreviousStart != netengine.StartAuto || state.LocalBlockCount != 0 {
		t.Fatalf("state: %+v", state)
	}

	// Undo puts the previous start types back and forgets the records.
	actions, err := w.RestoreBlockers(context.Background(), nil)
	if err != nil || len(actions) != 2 || engine.restored["RfwService"] != netengine.StartAuto || engine.restored["RfwFilter"] != netengine.StartDemand {
		t.Fatalf("restore: %v %v %v", actions, err, engine.restored)
	}
	state, _ = w.stateMgr.LoadState()
	if len(state.DisabledComponents) != 0 {
		t.Fatalf("records kept after restore: %+v", state.DisabledComponents)
	}
	if _, err := w.RestoreBlockers(context.Background(), []string{"Nope"}); err == nil {
		t.Fatal("restoring an unknown name did not fail")
	}
}

// A driver that stays loaded needs a restart: only with enable_reboot, and
// only once for the block.
func TestLocalBlockRebootsOnlyWhenAllowed(t *testing.T) {
	for _, enable := range []bool{false, true} {
		w, cfg, engine, _ := setupBlockerWatchdog(t)
		cfg.EnableReboot = enable
		engine.stayStuck = true
		for i := 0; i < 4; i++ {
			w.RunCheckCycle(context.Background())
		}
		if engine.rebootCalled != enable {
			t.Fatalf("enable_reboot=%v: rebootCalled=%v", enable, engine.rebootCalled)
		}
		if len(engine.disabled) != 2 {
			t.Fatalf("enable_reboot=%v: disabled %v, want each component once", enable, engine.disabled)
		}
	}
}

func TestLocalBlockObservationAndOff(t *testing.T) {
	for name, adjust := range map[string]func(*config.Config){
		"observation": func(c *config.Config) { c.ObservationMode = true },
		"off":         func(c *config.Config) { c.LocalBlockRecovery = false },
		"no ports":    func(c *config.Config) { c.AccessPorts = nil },
	} {
		t.Run(name, func(t *testing.T) {
			w, cfg, engine, _ := setupBlockerWatchdog(t)
			adjust(cfg)
			for i := 0; i < 3; i++ {
				w.RunCheckCycle(context.Background())
			}
			if len(engine.disabled) != 0 {
				t.Fatalf("disabled %v", engine.disabled)
			}
		})
	}
}

// A healthy host records its components; a component installed later is
// then chosen even with a valid signature, and long-known ones are not.
func TestLocalBlockUsesWorkingSnapshot(t *testing.T) {
	w, _, engine, checker := setupBlockerWatchdog(t)
	engine.blocking = false
	engine.comps = engine.comps[2:] // only Tailscale before RFW arrives
	engine.comps = append(engine.comps, netengine.Component{Name: "VendorAgent", Start: netengine.StartAuto, Image: `C:\Vendor\agent.exe`})
	engine.sigs["vendoragent"] = netengine.Signature{Valid: true, Signer: "Vendor", Status: "Valid"}
	checker.fastResult = canary.HealthResult{Healthy: true, InternetHealthy: true}
	w.RunCheckCycle(context.Background())
	if w.loadSnapshot() == nil {
		t.Fatal("no snapshot taken while the host worked")
	}

	// A day later a validly signed filter driver is installed and blocks.
	clock := w.clock.(*fakeClock)
	clock.currentTime = clock.currentTime.Add(24 * 60 * 60 * 1e9)
	engine.comps = append(engine.comps, netengine.Component{Name: "SignedFilter", Kernel: true, Running: true, Start: netengine.StartSystem, Image: `C:\Vendor\filter.sys`})
	engine.sigs["signedfilter"] = netengine.Signature{Valid: true, Signer: "Vendor", Status: "Valid"}
	engine.blocking = true
	checker.fastResult = canary.HealthResult{Healthy: false}
	w.RunCheckCycle(context.Background())
	w.RunCheckCycle(context.Background())
	if got := strings.Join(engine.disabled, ","); got != "SignedFilter" {
		t.Fatalf("disabled %q, want only the new SignedFilter", got)
	}
}

// RFW worked for a day (it is in the working snapshot), then began blocking
// with no change on the host. local_block_untrusted_drivers decides whether
// its test-signed driver is still suspected.
func TestLocalBlockUntrustedDriverAfterSnapshot(t *testing.T) {
	for _, untrusted := range []bool{true, false} {
		w, cfg, engine, checker := setupBlockerWatchdog(t)
		cfg.LocalBlockUntrustedDrivers = untrusted
		engine.blocking = false
		checker.fastResult = canary.HealthResult{Healthy: true, InternetHealthy: true}
		w.RunCheckCycle(context.Background())
		if w.loadSnapshot() == nil {
			t.Fatal("no snapshot taken while the host worked")
		}
		clock := w.clock.(*fakeClock)
		clock.currentTime = clock.currentTime.Add(24 * time.Hour)
		engine.blocking = true
		checker.fastResult = canary.HealthResult{Healthy: false}
		w.RunCheckCycle(context.Background())
		w.RunCheckCycle(context.Background())
		got := strings.Join(engine.disabled, ",")
		if untrusted && got != "RfwService,RfwFilter" {
			t.Fatalf("untrusted drivers on: disabled %q, want RfwService,RfwFilter", got)
		}
		if !untrusted && got != "" {
			t.Fatalf("untrusted drivers off: disabled %q, want nothing", got)
		}
	}
}

// While the internet checks pass, the host's own ports are tested every few
// minutes, not in every check; during an outage in every check.
func TestLocalAccessTestedLessOftenWhileHealthy(t *testing.T) {
	w, _, engine, checker := setupBlockerWatchdog(t)
	engine.blocking = false
	checker.fastResult = canary.HealthResult{Healthy: true, InternetHealthy: true}
	clock := w.clock.(*fakeClock)
	for i := 0; i < 4; i++ {
		w.RunCheckCycle(context.Background())
		clock.currentTime = clock.currentTime.Add(time.Minute)
	}
	if engine.tests != 1 {
		t.Fatalf("tested %d times in 4 healthy minutes, want 1", engine.tests)
	}
	clock.currentTime = clock.currentTime.Add(2 * time.Minute)
	w.RunCheckCycle(context.Background())
	if engine.tests != 2 {
		t.Fatalf("not tested again after 5 minutes: %d", engine.tests)
	}
	checker.fastResult = canary.HealthResult{Healthy: false}
	w.RunCheckCycle(context.Background())
	w.RunCheckCycle(context.Background())
	if engine.tests != 4 {
		t.Fatalf("not tested in every check during an outage: %d", engine.tests)
	}
}

// Only incoming connections blocked while the internet works (the probes
// pass): the healthy-path steps must not overwrite the block counter, so the
// second failed check acts.
func TestLocalBlockActsWhileInternetWorks(t *testing.T) {
	w, _, engine, checker := setupBlockerWatchdog(t)
	checker.fastResult = canary.HealthResult{Healthy: true, InternetHealthy: true}
	clock := w.clock.(*fakeClock)
	w.RunCheckCycle(context.Background())
	if len(engine.disabled) != 0 {
		t.Fatal("acted on the first failed check")
	}
	state, _ := w.stateMgr.LoadState()
	if state.LocalBlockCount != 1 {
		t.Fatalf("block counter not kept by a healthy check: %d", state.LocalBlockCount)
	}
	clock.currentTime = clock.currentTime.Add(time.Minute)
	w.RunCheckCycle(context.Background())
	if got := strings.Join(engine.disabled, ","); got != "RfwService,RfwFilter" {
		t.Fatalf("second check one minute later disabled %q", got)
	}
}

// proberMockEngine is a Linux-like engine: the self-probe goes over a
// virtual pair (LocalProber) and the components are rulesets and units.
type proberMockEngine struct {
	*blockerMockEngine
	sshOK bool
}

func (m *proberMockEngine) ProbeLocal(ctx context.Context, ip string, ports []int, timeout time.Duration) ([]netengine.PortProbe, error) {
	var out []netengine.PortProbe
	for _, p := range ports {
		out = append(out, netengine.PortProbe{Port: p, OK: m.sshOK && !m.blocking, Error: "timeout"})
	}
	return out, nil
}

// A port that never accepted the self-probe (a firewall admitting SSH only
// from elsewhere) is not a block; once it has passed, a failure is.
func TestLocalBlockNeedsPassedPortOnLinux(t *testing.T) {
	w, _, base, checker := setupBlockerWatchdog(t)
	engine := &proberMockEngine{blockerMockEngine: base}
	engine.comps = []netengine.Component{
		{Name: "nft:inet filter", Kind: netengine.KindRules, Kernel: true, Running: true, Start: netengine.StartAuto, Image: "sha256:aa"},
		{Name: "unit:sshd.service", Kind: netengine.KindUnit, Running: true, Start: netengine.StartAuto, Image: "/lib/systemd/system/sshd.service"},
	}
	w.SetEngine(engine)
	w.SetDialer(nil)
	ctx := context.Background()

	// Filtered from the start: never acted upon.
	for i := 0; i < 3; i++ {
		rep, _ := w.RunCheckCycle(ctx)
		if rep.LocalBlocked {
			t.Fatalf("a port that never passed counted as blocked")
		}
	}
	if len(engine.disabled) != 0 {
		t.Fatalf("disabled %v", engine.disabled)
	}

	// SSH works (snapshot taken), then a new table starts dropping it.
	engine.sshOK, engine.blocking = true, false
	checker.fastResult = canary.HealthResult{Healthy: true, InternetHealthy: true}
	clock := w.clock.(*fakeClock)
	clock.currentTime = clock.currentTime.Add(10 * time.Minute) // healthy hosts test every 5 min
	w.RunCheckCycle(ctx)
	if state, _ := w.stateMgr.LoadState(); len(state.LocalPortsOK) != 2 {
		t.Fatalf("passed ports not recorded: %+v", state.LocalPortsOK)
	}
	clock.currentTime = clock.currentTime.Add(24 * time.Hour)
	engine.comps = append(engine.comps, netengine.Component{Name: "nft:inet newblock", Kind: netengine.KindRules, Kernel: true, Running: true, Start: netengine.StartAuto, Image: "sha256:bb"})
	engine.blocking = true
	checker.fastResult = canary.HealthResult{Healthy: false}
	w.RunCheckCycle(ctx)
	w.RunCheckCycle(ctx)
	if got := strings.Join(engine.disabled, ","); got != "nft:inet newblock" {
		t.Fatalf("disabled %q, want the new table only", got)
	}
}
