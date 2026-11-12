//go:build windows

package netengine

import (
	"context"
	"os"
	"testing"

	"github.com/repentandliveholy/netriser/internal/config"
)

// Read-only check of the real PowerShell route listing; run on a Windows host
// with NETRISER_LIVE_POWERSHELL=1.
func TestLiveWindowsDefaultRoutesScript(t *testing.T) {
	if os.Getenv("NETRISER_LIVE_POWERSHELL") != "1" {
		t.Skip("set NETRISER_LIVE_POWERSHELL=1 to query this host's routes")
	}
	e := &WindowsEngine{cfg: config.DefaultConfig(), runner: &DefaultCommandRunner{}}
	out, err := e.runPowerShell(context.Background(), 0, windowsDefaultRoutesScript)
	t.Logf("output:\n%s", out)
	if err != nil {
		t.Fatalf("route listing failed: %v", err)
	}
	routes := ParseWindowsRoutes(out)
	if len(routes) == 0 {
		t.Fatal("no default routes parsed")
	}
	for _, r := range routes {
		t.Logf("%+v overlay=%t", r, r.isOverlay())
	}
	t.Logf("rogue: %+v", WindowsRogueRoutes(routes, config.DefaultConfig()))
}

// Read-only check of baseline detection on a real host (the saved baseline
// goes to a temporary directory); run with NETRISER_LIVE_POWERSHELL=1.
func TestLiveWindowsDetectBaseline(t *testing.T) {
	if os.Getenv("NETRISER_LIVE_POWERSHELL") != "1" {
		t.Skip("set NETRISER_LIVE_POWERSHELL=1 to detect this host's uplink")
	}
	cfg := config.DefaultConfig()
	cfg.StateDir = t.TempDir()
	e := &WindowsEngine{cfg: cfg, runner: &DefaultCommandRunner{}}
	b, err := e.DetectBaseline(context.Background())
	t.Logf("baseline: %+v", b)
	if err != nil || !b.IsValid() {
		t.Fatalf("baseline not detected: %v", err)
	}
	if ip := interfaceIPv4(b.Interface); ip != b.IP {
		t.Fatalf("system API gives %q for %s, baseline has %q", ip, b.Interface, b.IP)
	}
}
