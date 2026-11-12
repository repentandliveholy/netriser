package netengine

import (
	"context"
	"strings"
	"testing"

	"github.com/repentandliveholy/netriser/internal/config"
)

func TestBuiltinOverlayClassification(t *testing.T) {
	defer ConfigureOverlays(nil)
	ConfigureOverlays(nil)
	for iface, want := range map[string]string{
		"wt0": "NetBird", "tailscale0": "Tailscale", "ztuga1234": "ZeroTier", "nebula1": "Nebula",
		"wg0": "WireGuard", "wg-mesh": "WireGuard", "wg0-mullvad": "Mullvad", "nordlynx": "NordVPN",
		"CloudflareWARP": "Cloudflare WARP", "tun0": "OpenVPN", "tap1": "OpenVPN", "ipsec0": "IPsec",
		"xfrm0": "IPsec", "vti1": "IPsec", "cscotun0": "Cisco AnyConnect", "gpd0": "GlobalProtect",
		"utun4": "Generic tunnel", "feth4426": "ZeroTier", "ygg0": "Yggdrasil",
	} {
		o, ok := ClassifyUnix(iface)
		if !ok || o.Name != want {
			t.Errorf("%s: got %q (%t), want %s", iface, o.Name, ok, want)
		}
	}
	// ppp0 is commonly the physical PPPoE uplink and must stay eligible.
	for _, iface := range []string{"eth0", "enp3s0", "en0", "wlan0", "ppp0", "bond0", "eno1"} {
		if o, ok := ClassifyUnix(iface); ok {
			t.Errorf("%s classified as overlay %s", iface, o.Name)
		}
	}
}

func TestOverlayKindsAndBypass(t *testing.T) {
	cfg := config.DefaultConfig()
	if !actionableUnixOverlay(cfg, "tailscale0") {
		t.Error("mesh overlay default route must be actionable")
	}
	for _, iface := range []string{"wg0", "tun0", "utun3", "ipsec0", "wg0-mullvad"} {
		if actionableUnixOverlay(cfg, iface) {
			t.Errorf("%s actionable without allow_vpn_bypass", iface)
		}
	}
	cfg.AllowVPNBypass = true
	if !actionableUnixOverlay(cfg, "wg0") {
		t.Error("allow_vpn_bypass ignored")
	}
	cfg.AllowedDefaultInterfaces = []string{"wg0"}
	if actionableUnixOverlay(cfg, "wg0") {
		t.Error("allowed_default_interfaces ignored")
	}
}

func TestConfiguredOverlaysPrecedeBuiltins(t *testing.T) {
	defer ConfigureOverlays(nil)
	cfg := config.DefaultConfig()
	cfg.Overlays = []config.OverlayConfig{
		{Name: "corp", Interface: "^corp[0-9]+$", Kind: "mesh", Services: []string{"corp@{iface}"}},
		{Name: "my-tun", Interface: "^tun9$", Kind: "vpn", Services: []string{"myvpn"}},
	}
	ConfigureOverlays(cfg)
	o, ok := ClassifyUnix("corp1")
	if !ok || o.Kind != KindMesh || o.Services("linux", "corp1")[0] != "corp@corp1" {
		t.Fatalf("custom overlay: %+v %t", o, ok)
	}
	if o, _ := ClassifyUnix("tun9"); o.Name != "my-tun" {
		t.Fatalf("custom definition must win over OpenVPN: %s", o.Name)
	}
	if o, _ := ClassifyUnix("tun0"); o.Name != "OpenVPN" {
		t.Fatalf("built-ins lost: %s", o.Name)
	}
	if !IsIgnoredInterface("corp1") {
		t.Fatal("custom overlay chosen as physical uplink candidate")
	}
}

func TestLinuxQuarantineStopsWireGuardOnlyWithBypass(t *testing.T) {
	for _, bypass := range []bool{false, true} {
		e, r, b := linuxFixture(t)
		e.cfg.AllowVPNBypass = bypass
		if err := SaveBaseline(e.cfg.StateDir, b); err != nil {
			t.Fatal(err)
		}
		r.replies["ip -4 route show 0.0.0.0/1"] = "0.0.0.0/1 dev wg0 scope link"
		_, _ = e.QuarantineMeshServices(context.Background())
		calls := strings.Join(r.calls, "\n")
		if stopped := strings.Contains(calls, "systemctl stop wg-quick@wg0"); stopped != bypass {
			t.Fatalf("bypass=%t stopped=%t\n%s", bypass, stopped, calls)
		}
	}
}

func TestLinuxMonitoredServicesFilter(t *testing.T) {
	e, r, b := linuxFixture(t)
	e.cfg.MonitoredServices = []string{"tailscaled"}
	if err := SaveBaseline(e.cfg.StateDir, b); err != nil {
		t.Fatal(err)
	}
	r.replies["ip -j -4 route show default"] = `[{"dst":"default","dev":"wt0","gateway":"100.1.1.1"}]`
	_, _ = e.QuarantineMeshServices(context.Background())
	if strings.Contains(strings.Join(r.calls, "\n"), "systemctl stop netbird") {
		t.Fatal("service outside monitored_services stopped")
	}
}
