//go:build windows

package netengine

import (
	"context"
	"strings"
	"testing"

	"github.com/repentandliveholy/netriser/internal/config"
)

// fakeWindowsHost models default routes and services behind PowerShell.
type fakeWindowsHost struct {
	routes   []string          // "alias|prefix|description"
	services map[string]bool   // name -> running
	adapters map[string]string // alias -> Get-NetAdapter Status
	scripts  []string
}

func (h *fakeWindowsHost) Run(_ context.Context, name string, args ...string) (string, error) {
	script := ""
	if len(args) > 0 {
		script = args[len(args)-1]
	}
	h.scripts = append(h.scripts, script)
	switch {
	case strings.Contains(script, "Enable-NetAdapter -Name $name"):
		for alias, status := range h.adapters {
			if strings.Contains(script, psQuote(alias)) {
				prefix := "RESTARTED\n"
				if status == "Disabled" {
					prefix = "ENABLED\n"
				}
				h.adapters[alias] = "Up"
				return prefix + "UP 192.168.1.20", nil
			}
		}
		return "MISSING", nil
	case strings.Contains(script, "New-NetRoute"):
		h.routes = append(h.routes, "Ethernet|0.0.0.0/0|25|Realtek PCIe GBE Family Controller")
		return "", nil
	case strings.Contains(script, "Get-NetRoute -DestinationPrefix $p"):
		return strings.Join(h.routes, "\n"), nil
	case strings.HasPrefix(script, "Remove-NetRoute"):
		var kept []string
		for _, r := range h.routes {
			parts := strings.SplitN(r, "|", 4)
			if !strings.Contains(script, psQuote(parts[1])) || !strings.Contains(script, psQuote(parts[0])) {
				kept = append(kept, r)
			}
		}
		h.routes = kept
		return "", nil
	case strings.Contains(script, "Stop-Service"):
		for svc, running := range h.services {
			if strings.Contains(script, psQuote(svc)) {
				if !running {
					return "NOT_RUNNING", nil
				}
				h.services[svc] = false
				return "STOPPED", nil
			}
		}
		return "MISSING", nil
	case strings.Contains(script, "Start-Service"):
		for svc := range h.services {
			if strings.Contains(script, psQuote(svc)) {
				h.services[svc] = true
				return "", nil
			}
		}
		return "MISSING", nil
	}
	return "", nil
}

func newFakeWindowsEngine(h *fakeWindowsHost, allowed ...string) *WindowsEngine {
	cfg := config.DefaultConfig()
	cfg.AllowedDefaultInterfaces = allowed
	return &WindowsEngine{cfg: cfg, runner: h}
}

func TestWindowsWireGuardKillSwitchTunnelIsStoppedAtStageOne(t *testing.T) {
	const wgService = "WireGuardTunnel$wg-hetzner-ovs-server-1"
	h := &fakeWindowsHost{
		routes: []string{
			"Ethernet|0.0.0.0/0|25|Intel(R) Ethernet",
			"wg-hetzner-ovs-server-1|0.0.0.0/0|5|WireGuard Tunnel",
		},
		services: map[string]bool{wgService: true, "Tailscale": true},
	}
	e := newFakeWindowsEngine(h)
	ctx := context.Background()

	// Route removal cannot lift the kill-switch: stage 1 stops the tunnel.
	actions, _ := e.SurgicalCleanRoutes(ctx, Baseline{})
	if h.services[wgService] {
		t.Fatalf("WireGuard tunnel still running after stage 1: %+v", actions)
	}
	found := false
	for _, a := range actions {
		if a.Type == ActionQuarantineService && a.Target == wgService && a.Status == ActionExecuted {
			found = true
		}
	}
	if !found {
		t.Fatalf("stage 1 must report the stopped tunnel for the quarantine record: %+v", actions)
	}
	if !h.services["Tailscale"] {
		t.Fatal("Tailscale was stopped without rogue-route evidence")
	}

	// Recovery restores exactly the recorded service.
	if _, err := e.RestoreMeshServices(ctx, []string{wgService}); err != nil {
		t.Fatal(err)
	}
	if !h.services[wgService] {
		t.Fatal("WireGuard tunnel service not restarted")
	}
}

func TestWindowsWireGuardRouteRemovedWhenQuarantineDisabled(t *testing.T) {
	const wgService = "WireGuardTunnel$wg-test"
	h := &fakeWindowsHost{
		routes:   []string{"Ethernet|0.0.0.0/0|25|Intel(R) Ethernet", "wg-test|0.0.0.0/0|5|WireGuard Tunnel"},
		services: map[string]bool{wgService: true},
	}
	e := newFakeWindowsEngine(h)
	e.cfg.AllowServiceQuarantine = false
	_, _ = e.SurgicalCleanRoutes(context.Background(), Baseline{})
	if !h.services[wgService] || len(h.routes) != 1 {
		t.Fatalf("with quarantine disabled only the route may be removed: routes=%v services=%v", h.routes, h.services)
	}
}

func TestWindowsQuarantineWithoutEvidencePreservesOverlays(t *testing.T) {
	h := &fakeWindowsHost{
		routes:   []string{"Ethernet|0.0.0.0/0|25|Intel(R) Ethernet"},
		services: map[string]bool{"Tailscale": true},
	}
	e := newFakeWindowsEngine(h)
	if _, err := e.QuarantineMeshServices(context.Background()); err == nil {
		t.Fatal("quarantine without evidence must report preserved overlays")
	}
	if !h.services["Tailscale"] {
		t.Fatal("overlay stopped without evidence")
	}
	for _, s := range h.scripts {
		if strings.Contains(s, "Disable-NetAdapter") {
			t.Fatal("adapter disabled without evidence")
		}
	}
}

func TestWindowsAllowedDefaultInterfaceIsUntouched(t *testing.T) {
	h := &fakeWindowsHost{
		routes:   []string{"Tailscale|0.0.0.0/0|5|Tailscale Tunnel"},
		services: map[string]bool{"Tailscale": true},
	}
	e := newFakeWindowsEngine(h, "Tailscale")
	_, _ = e.SurgicalCleanRoutes(context.Background(), Baseline{})
	_, _ = e.QuarantineMeshServices(context.Background())
	if len(h.routes) != 1 || !h.services["Tailscale"] {
		t.Fatalf("allowed exit-node interface was modified: routes=%v services=%v", h.routes, h.services)
	}
}

func TestWindowsRestoreOfRemovedServiceIsNotRetried(t *testing.T) {
	h := &fakeWindowsHost{services: map[string]bool{}}
	e := newFakeWindowsEngine(h)
	actions, err := e.RestoreMeshServices(context.Background(), []string{"WireGuardTunnel$gone"})
	if err != nil || len(actions) != 1 || actions[0].Status != ActionNotNeeded {
		t.Fatalf("removed service should be treated as restored: %+v %v", actions, err)
	}
}

func TestWindowsDisabledEthernetIsKnownAndReEnabled(t *testing.T) {
	h := &fakeWindowsHost{adapters: map[string]string{"Ethernet": "Disabled"}}
	e := newFakeWindowsEngine(h)
	e.cfg.StateDir = t.TempDir()
	saved := Baseline{Interface: "Ethernet", IP: "192.168.1.20", Gateway: "192.168.1.1"}
	if err := SaveBaseline(e.cfg.StateDir, saved); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Disabled from Network Connections: no address and no default route.
	b, err := e.DetectBaseline(ctx)
	if err == nil || b.IsValid() {
		t.Fatalf("disabled adapter must not yield a valid baseline: %+v", b)
	}
	if !b.HasKnownInterface() || b.Interface != "Ethernet" || b.Gateway != "192.168.1.1" {
		t.Fatalf("disabled uplink must remain a known interface for stage 3: %+v", b)
	}

	if err := e.RestartNetworkStack(ctx, b); err != nil {
		t.Fatal(err)
	}
	if h.adapters["Ethernet"] != "Up" {
		t.Fatal("disabled Ethernet adapter was not enabled")
	}
	if len(h.routes) != 1 {
		t.Fatalf("default route through the known gateway not restored: %v", h.routes)
	}
}

func TestWindowsRestartReportsMissingAdapter(t *testing.T) {
	h := &fakeWindowsHost{adapters: map[string]string{}}
	e := newFakeWindowsEngine(h)
	if err := e.RestartNetworkStack(context.Background(), Baseline{Interface: "Ethernet"}); err == nil {
		t.Fatal("missing adapter reported as recovered")
	}
}
