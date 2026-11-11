package netengine

import (
	"context"
	"strings"
	"testing"

	"github.com/repentandliveholy/netriser/internal/config"
)

func TestParseLinuxRoutesJSON(t *testing.T) {
	jsonSample := `[
  {"dst":"default","gateway":"192.168.1.1","dev":"eth0","protocol":"dhcp","metric":100},
  {"dst":"default","gateway":"10.0.0.1","dev":"eth1","protocol":"dhcp","metric":200},
  {"dst":"192.168.1.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.168.1.50"}
]`
	routes, err := ParseLinuxRoutesJSON([]byte(jsonSample))
	if err != nil {
		t.Fatalf("failed to parse routes JSON: %v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if routes[0].Destination != "default" || routes[0].Gateway != "192.168.1.1" || routes[0].Metric != 100 {
		t.Fatalf("unexpected route[0]: %+v", routes[0])
	}
	if routes[1].Interface != "eth1" || routes[1].Metric != 200 {
		t.Fatalf("unexpected route[1]: %+v", routes[1])
	}
}

func TestParseLinuxRoutesText(t *testing.T) {
	textSample := `default via 192.168.1.1 dev eth0 proto dhcp metric 100
default via 10.0.0.1 dev eth1 proto dhcp metric 200
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50`

	routes := ParseLinuxRoutesText(textSample)
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if routes[0].Gateway != "192.168.1.1" || routes[0].Interface != "eth0" || routes[0].Metric != 100 {
		t.Fatalf("unexpected route[0]: %+v", routes[0])
	}
}

func TestParseLinuxAddrJSON(t *testing.T) {
	jsonSample := `[
  {
    "ifname": "eth0",
    "operstate": "UP",
    "addr_info": [
      {"family": "inet", "local": "192.168.1.50", "scope": "global"},
      {"family": "inet6", "local": "fe80::1", "scope": "link"}
    ]
  }
]`
	ip := ParseLinuxAddrJSON([]byte(jsonSample))
	if ip != "192.168.1.50" {
		t.Fatalf("expected 192.168.1.50, got %q", ip)
	}
}

func TestParseLinuxRules(t *testing.T) {
	rulesSample := `0:	from all lookup local
100:	from 192.168.1.50 lookup 200
101:	from 100.64.0.1 lookup 52
200:	from all fwmark 0x1 lookup 100
32766:	from all lookup main
32767:	from all lookup default`

	rules := ParseLinuxRules(rulesSample)
	if len(rules) != 6 {
		t.Fatalf("expected 6 rules, got %d", len(rules))
	}
	if rules[1].Priority != 100 || !strings.Contains(rules[1].Selector, "from 192.168.1.50 lookup 200") {
		t.Fatalf("unexpected rule[1]: %+v", rules[1])
	}
	if rules[2].Priority != 101 || !strings.Contains(rules[2].Selector, "lookup 52") {
		t.Fatalf("unexpected rule[2]: %+v", rules[2])
	}
}

func TestDarwinParsers(t *testing.T) {
	routeGetOut := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>`

	gw, iface := ParseDarwinRouteGetDefault(routeGetOut)
	if gw != "192.168.1.1" {
		t.Fatalf("expected gateway 192.168.1.1, got %q", gw)
	}
	if iface != "en0" {
		t.Fatalf("expected interface en0, got %q", iface)
	}

	netstatOut := `Routing tables
Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
default            10.200.0.1         UGSc         utun3
0/1                10.200.0.1         UGSc         utun3
127.0.0.1          127.0.0.1          UH             lo0`

	routes := ParseDarwinNetstat(netstatOut)
	if len(routes) != 4 {
		t.Fatalf("expected 4 routes, got %d", len(routes))
	}
	if routes[0].Destination != "default" || routes[0].Interface != "en0" {
		t.Fatalf("unexpected route[0]: %+v", routes[0])
	}
	if routes[1].Destination != "default" || routes[1].Interface != "utun3" {
		t.Fatalf("unexpected route[1]: %+v", routes[1])
	}
}

func TestLinuxMultipleNICSelectsLowestMetric(t *testing.T) {
	jsonSample := `[
  {"dst":"default","gateway":"10.0.0.1","dev":"eth1","metric":200},
  {"dst":"default","gateway":"192.168.1.1","dev":"eth0","metric":50}
]`
	routes, err := ParseLinuxRoutesJSON([]byte(jsonSample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var bestRoute *RouteEntry
	for _, r := range routes {
		if r.Interface != "" && !IsIgnoredInterface(r.Interface) {
			if bestRoute == nil || r.Metric < bestRoute.Metric {
				rc := r
				bestRoute = &rc
			}
		}
	}

	if bestRoute == nil {
		t.Fatal("expected best route")
	}
	if bestRoute.Interface != "eth0" {
		t.Fatalf("expected interface eth0 with lowest metric 50, got %q", bestRoute.Interface)
	}
	if bestRoute.Gateway != "192.168.1.1" {
		t.Fatalf("expected gateway 192.168.1.1, got %q", bestRoute.Gateway)
	}
}

func TestAllowedExitNodeProtectedFromDeletion(t *testing.T) {
	runner := NewScriptedRunner()
	// Two default routes: physical en0 and an authorized VPN exit-node on utun4
	runner.On("netstat -rn -f inet", func(ctx context.Context, args []string) (string, error) {
		return `Routing tables
Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
default            10.200.0.1         UGSc         utun4
0/1                10.200.0.1         UGSc         utun4`, nil
	})

	deletedRoutes := []string{}
	runner.On("route -n delete", func(ctx context.Context, args []string) (string, error) {
		deletedRoutes = append(deletedRoutes, strings.Join(args, " "))
		return "deleted", nil
	})

	cfg := config.DefaultConfig()
	// Explicitly authorize utun4 as an allowed exit-node interface
	cfg.AllowedDefaultInterfaces = []string{"utun4"}
	engine := NewEngineWithRunner(cfg, runner)

	actions, err := engine.SurgicalCleanRoutes(context.Background(), Baseline{
		Interface: "en0",
		Gateway:   "192.168.1.1",
		IP:        "192.168.1.50",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// utun4 default route and 0/1 should NOT have been deleted
	for _, del := range deletedRoutes {
		if strings.Contains(del, "utun4") {
			t.Fatalf("expected authorized exit node utun4 to NOT be deleted, but found deletion: %s", del)
		}
	}
	_ = actions
}

func TestPolicyRoutingCollisionDetection(t *testing.T) {
	ruleState := `0:	from all lookup local
100:	from 192.168.1.50 lookup 200
101:	from 172.16.0.1 lookup 999
32766:	from all lookup main`

	rules := ParseLinuxRules(ruleState)

	// Check if rule for 192.168.1.50 lookup 200 priority 100 exists
	expectedSelector := "from 192.168.1.50 lookup 200"
	foundOurRule := false
	thirdPartyPrio101Preserved := false

	for _, r := range rules {
		if r.Priority == 100 && strings.Contains(r.Selector, expectedSelector) {
			foundOurRule = true
		}
		if r.Priority == 101 && strings.Contains(r.Selector, "lookup 999") {
			thirdPartyPrio101Preserved = true
		}
	}

	if !foundOurRule {
		t.Errorf("expected to find our rule")
	}
	if !thirdPartyPrio101Preserved {
		t.Errorf("expected third-party priority 101 to be distinguished")
	}
}
