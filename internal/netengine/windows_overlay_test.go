package netengine

import "testing"

func TestWindowsRogueRoutesClassification(t *testing.T) {
	out := "Ethernet|0.0.0.0/0|Intel(R) Ethernet Connection I219-V\r\n" +
		"wg-hetzner-ovs-server-1|0.0.0.0/0|WireGuard Tunnel\r\n" +
		"Tailscale|0.0.0.0/0|Tailscale Tunnel\r\n" +
		"vEthernet (External)|0.0.0.0/0|Hyper-V Virtual Ethernet Adapter\r\n" +
		"OpenVPN TAP|0.0.0.0/1|TAP-Windows Adapter V9\r\n" +
		"garbage line\r\n"
	routes := ParseWindowsRoutes(out)
	if len(routes) != 5 {
		t.Fatalf("parsed %d routes: %+v", len(routes), routes)
	}
	rogue := WindowsRogueRoutes(routes, nil)
	got := map[string]bool{}
	for _, r := range rogue {
		got[r.Alias] = true
	}
	for _, alias := range []string{"wg-hetzner-ovs-server-1", "Tailscale", "OpenVPN TAP"} {
		if !got[alias] {
			t.Errorf("%s not treated as rogue overlay route", alias)
		}
	}
	for _, alias := range []string{"Ethernet", "vEthernet (External)"} {
		if got[alias] {
			t.Errorf("%s must not be treated as a rogue overlay route", alias)
		}
	}

	allowed := func(alias string) bool { return alias == "Tailscale" }
	for _, r := range WindowsRogueRoutes(routes, allowed) {
		if r.Alias == "Tailscale" {
			t.Fatal("allowed_default_interfaces was ignored")
		}
	}
}

func TestWindowsOverlayServiceNames(t *testing.T) {
	cases := []struct {
		route WindowsRoute
		want  string
	}{
		{WindowsRoute{Alias: "wg-hetzner-ovs-server-1", Description: "WireGuard Tunnel"}, "WireGuardTunnel$wg-hetzner-ovs-server-1"},
		{WindowsRoute{Alias: "Tailscale", Description: "Tailscale Tunnel"}, "Tailscale"},
		{WindowsRoute{Alias: "ZeroTier One [abc]", Description: "ZeroTier Virtual Port"}, "ZeroTierOneService"},
		{WindowsRoute{Alias: "wt0", Description: "Wintun Userspace Tunnel"}, "netbird"},
		{WindowsRoute{Alias: "nebula1", Description: "Wintun Userspace Tunnel"}, "nebula"},
		{WindowsRoute{Alias: "OpenVPN TAP", Description: "TAP-Windows Adapter V9"}, ""},
	}
	for _, c := range cases {
		if got := WindowsOverlayService(c.route); got != c.want {
			t.Errorf("%s: got %q, want %q", c.route.Alias, got, c.want)
		}
	}
}

func TestPSQuote(t *testing.T) {
	if got := psQuote("it's $x"); got != "'it''s $x'" {
		t.Fatalf("psQuote: %s", got)
	}
}
