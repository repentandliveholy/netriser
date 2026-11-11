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
	routes   []string        // "alias|prefix|description"
	services map[string]bool // name -> running
	scripts  []string
}

func (h *fakeWindowsHost) Run(_ context.Context, name string, args ...string) (string, error) {
	script := ""
	if len(args) > 0 {
		script = args[len(args)-1]
	}
	h.scripts = append(h.scripts, script)
	switch {
	case strings.Contains(script, "Get-NetRoute -DestinationPrefix $p"):
		return strings.Join(h.routes, "\n"), nil
	case strings.HasPrefix(script, "Remove-NetRoute"):
		var kept []string
		for _, r := range h.routes {
			parts := strings.SplitN(r, "|", 3)
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

func TestWindowsWireGuardKillSwitchTunnelIsStoppedAfterRouteCleanup(t *testing.T) {
	const wgService = "WireGuardTunnel$wg-hetzner-ovs-server-1"
	h := &fakeWindowsHost{
		routes: []string{
			"Ethernet|0.0.0.0/0|Intel(R) Ethernet",
			"wg-hetzner-ovs-server-1|0.0.0.0/0|WireGuard Tunnel",
		},
		services: map[string]bool{wgService: true, "Tailscale": true},
	}
	e := newFakeWindowsEngine(h)
	ctx := context.Background()

	// Stage 1 removes the rogue route; the kill-switch keeps blocking traffic.
	actions, _ := e.SurgicalCleanRoutes(ctx, Baseline{})
	if len(h.routes) != 1 || !strings.HasPrefix(h.routes[0], "Ethernet|") {
		t.Fatalf("rogue route not removed: %v (%+v)", h.routes, actions)
	}

	// Stage 2 must still identify the tunnel from stage 1 evidence.
	actions, err := e.QuarantineMeshServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.services[wgService] {
		t.Fatalf("WireGuard tunnel service still running: %+v", actions)
	}
	if !h.services["Tailscale"] {
		t.Fatal("Tailscale was stopped without rogue-route evidence")
	}
	if len(actions) != 1 || actions[0].Target != wgService || actions[0].Status != ActionExecuted {
		t.Fatalf("unexpected quarantine actions: %+v", actions)
	}

	// Recovery restores exactly the recorded service.
	if _, err := e.RestoreMeshServices(ctx, []string{wgService}); err != nil {
		t.Fatal(err)
	}
	if !h.services[wgService] {
		t.Fatal("WireGuard tunnel service not restarted")
	}
}

func TestWindowsQuarantineWithoutEvidencePreservesOverlays(t *testing.T) {
	h := &fakeWindowsHost{
		routes:   []string{"Ethernet|0.0.0.0/0|Intel(R) Ethernet"},
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
		routes:   []string{"Tailscale|0.0.0.0/0|Tailscale Tunnel"},
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
