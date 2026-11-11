package netengine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/repentandliveholy/netriser/internal/config"
)

type linuxRunner struct {
	replies  map[string]string
	failures map[string]error
	calls    []string
	hook     func(string)
}

func (r *linuxRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, cmd)
	if r.hook != nil {
		r.hook(cmd)
	}
	return r.replies[cmd], r.failures[cmd]
}
func linuxFixture(t *testing.T) (*LinuxEngine, *linuxRunner, Baseline) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.StateDir = t.TempDir()
	r := &linuxRunner{replies: map[string]string{}, failures: map[string]error{}}
	b := Baseline{Interface: "eth0", IP: "198.51.100.20", Gateway: "192.168.0.1", Source: BaselineSourceCached}
	r.replies["ip -j -4 addr show dev eth0"] = `[{"ifname":"eth0","operstate":"DOWN","addr_info":[{"family":"inet","local":"198.51.100.20","prefixlen":32,"scope":"global"}]}]`
	r.replies["ip -j -4 addr show dev ens4"] = `[{"ifname":"ens4","addr_info":[{"family":"inet","local":"192.168.40.20","scope":"global"}]}]`
	r.replies["ip -j -4 route show default"] = `[]`
	r.replies["ip -o link show dev eth0"] = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
	return &LinuxEngine{cfg: cfg, runner: r}, r, b
}
func TestLinuxRescueLostDefaultRetainsDownWAN(t *testing.T) {
	e, r, saved := linuxFixture(t)
	if err := SaveBaseline(e.cfg.StateDir, saved); err != nil {
		t.Fatal(err)
	}
	b, err := e.DetectBaseline(context.Background())
	if err != nil || b.Interface != "eth0" || b.Gateway != "192.168.0.1" || b.IP != saved.IP {
		t.Fatalf("lost WAN baseline: %+v %v", b, err)
	}
	if _, err := e.SurgicalCleanRoutes(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.calls, "\n")
	for _, want := range []string{
		"ip link set dev eth0 up",
		"ip route replace default via 192.168.0.1 dev eth0 onlink",
		"ip route replace default via 192.168.0.1 dev eth0 table 200 onlink",
		"ip rule add from 198.51.100.20 lookup 200 priority 100",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing recovery command %q\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "ens4") || strings.Contains(calls, "default dev") {
		t.Fatalf("unsafe recovery:\n%s", calls)
	}
}
func TestLinuxBaselineDoesNotGuessOrMixInterfaces(t *testing.T) {
	for _, scenario := range []string{"no cache", "override another interface", "changed address", "cached WAN beats alternate default"} {
		t.Run(scenario, func(t *testing.T) {
			e, r, saved := linuxFixture(t)
			if scenario != "no cache" {
				if err := SaveBaseline(e.cfg.StateDir, saved); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "override another interface":
				e.cfg.ManagementInterface = "ens4"
			case "changed address":
				r.replies["ip -j -4 addr show dev eth0"] = `[{"addr_info":[{"local":"84.32.25.77","scope":"global"}]}]`
			case "cached WAN beats alternate default":
				r.replies["ip -j -4 route show default"] = `[{"dst":"default","gateway":"192.168.40.1","dev":"ens4"}]`
			}
			b, err := e.DetectBaseline(context.Background())
			if scenario == "cached WAN beats alternate default" {
				if err != nil || b.Interface != "eth0" || b.Gateway != saved.Gateway {
					t.Fatalf("cache replaced: %+v %v", b, err)
				}
			} else if err == nil {
				t.Fatalf("guessed unsafe baseline: %+v", b)
			}
			loaded, err := LoadSavedBaseline(e.cfg.StateDir)
			if scenario != "no cache" && (err != nil || loaded != saved) {
				t.Fatalf("discovery mutated cache: %+v %v", loaded, err)
			}
		})
	}
}
func TestLinuxPinnedInterfaceUsesOnlyItsGateway(t *testing.T) {
	e, r, _ := linuxFixture(t)
	e.cfg.ManagementInterface = "eth0"
	r.replies["ip -j -4 route show default"] = `[{"dst":"default","gateway":"192.168.40.1","dev":"ens4","metric":1},{"dst":"default","gateway":"192.168.0.1","dev":"eth0","metric":100}]`
	b, err := e.DetectBaseline(context.Background())
	if err != nil || b.Gateway != "192.168.0.1" || b.Source != BaselineSourceConfig {
		t.Fatalf("wrong pinned baseline %+v %v", b, err)
	}
}
func TestLinuxRejectsGatewaylessMutations(t *testing.T) {
	e, r, b := linuxFixture(t)
	b.Gateway = ""
	if err := e.ApplyPolicyRouting(context.Background(), b); err == nil {
		t.Fatal("accepted gatewayless policy")
	}
	if _, err := e.SurgicalCleanRoutes(context.Background(), b); err == nil {
		t.Fatal("accepted gatewayless repair")
	}
	if len(r.calls) != 0 {
		t.Fatalf("mutated with no gateway: %v", r.calls)
	}
}
func TestLinuxPolicyPreservesSourceRulesAndReportsFailure(t *testing.T) {
	e, r, b := linuxFixture(t)
	r.replies["ip rule show"] = "100: from 84.32.25.75 lookup 200\n101: from 100.71.187.60 lookup 52\n105: from all lookup main suppress_prefixlength 0\n"
	if err := e.ApplyPolicyRouting(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range r.calls {
		if strings.Contains(cmd, "rule del") {
			t.Fatalf("deleted management rule: %s", cmd)
		}
	}
	r.failures["ip route replace default via 192.168.0.1 dev eth0 table 200 onlink"] = errors.New("permission denied")
	r.calls = nil
	if err := e.ApplyPolicyRouting(context.Background(), b); err == nil {
		t.Fatal("route failure hidden")
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "rule add") {
		t.Fatal("added source rule after failed route")
	}
	r.failures = map[string]error{}
	r.replies["ip rule show"] = "100: from all lookup 2000"
	r.calls = nil
	if err := e.ApplyPolicyRouting(context.Background(), b); err == nil {
		t.Fatal("foreign priority collision accepted")
	}
	if len(r.calls) != 1 {
		t.Fatalf("modified routing on collision: %v", r.calls)
	}
}
func TestLinuxRecoveryReconfiguresNetworkdAndBothTables(t *testing.T) {
	e, r, b := linuxFixture(t)
	if err := e.RestartNetworkStack(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.calls, "\n")
	for _, want := range []string{"networkctl reconfigure eth0", "ip route replace default via 192.168.0.1 dev eth0 onlink", "ip route replace default via 192.168.0.1 dev eth0 table 200 onlink"} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %s", want)
		}
	}
	r.failures["networkctl reconfigure eth0"] = errors.New("reconfigure failed")
	r.failures["systemctl restart systemd-networkd"] = errors.New("restart failed")
	if err := e.RestartNetworkStack(context.Background(), b); err == nil {
		t.Fatal("network restart error hidden")
	}
}
func TestLinuxQuarantinePreservesUnrelatedOverlays(t *testing.T) {
	for _, scenario := range []string{"WAN outage", "netbird hijack", "authorized exit", "WAN down", "unknown WAN"} {
		t.Run(scenario, func(t *testing.T) {
			e, r, b := linuxFixture(t)
			if scenario != "unknown WAN" {
				if err := SaveBaseline(e.cfg.StateDir, b); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "netbird hijack" || scenario == "authorized exit" {
				r.replies["ip -j -4 route show default"] = `[{"dst":"default","dev":"wt0","gateway":"100.1.1.1"}]`
			}
			if scenario == "authorized exit" {
				e.cfg.AllowedDefaultInterfaces = []string{"wt0"}
			}
			if scenario == "WAN down" {
				r.replies["ip -o link show dev eth0"] = "2: eth0: <BROADCAST,MULTICAST> mtu 1500"
			}
			acts, err := e.QuarantineMeshServices(context.Background())
			if scenario == "unknown WAN" || scenario == "WAN down" {
				if err == nil {
					t.Fatal("unsafe quarantine accepted")
				}
			}
			calls := strings.Join(r.calls, "\n")
			for _, cmd := range r.calls {
				if strings.Contains(cmd, " stop ") && (scenario != "netbird hijack" || (cmd != "systemctl stop netbird" && cmd != "systemctl stop netbird-client")) {
					t.Fatalf("stopped unrelated overlay %s: %+v", cmd, acts)
				}
				if strings.Contains(cmd, " down") || strings.Contains(cmd, " flush ") {
					t.Fatalf("unsafe global cleanup: %s", cmd)
				}
			}
			if scenario == "netbird hijack" && !strings.Contains(calls, "systemctl stop netbird") {
				t.Fatalf("hijacker not quarantined: %+v %v", acts, err)
			}
		})
	}
}
func TestLinuxRepairPreservesAlternatePhysicalDefault(t *testing.T) {
	e, r, b := linuxFixture(t)
	r.replies["ip -j -4 route show default"] = `[{"dst":"default","gateway":"192.168.40.1","dev":"ens4","metric":200}]`
	_, err := e.SurgicalCleanRoutes(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "route del default via 192.168.40.1") {
		t.Fatal("deleted alternate uplink")
	}
}

func TestLinuxAddresslessWANUsesNetworkManagerWithoutSwitchingAdapters(t *testing.T) {
	e, r, saved := linuxFixture(t)
	if err := SaveBaseline(e.cfg.StateDir, saved); err != nil {
		t.Fatal(err)
	}
	original := r.replies["ip -j -4 addr show dev eth0"]
	r.replies["ip -j -4 addr show dev eth0"] = "[]"
	r.replies["ip -j -4 route show default"] = `[{"dst":"default","gateway":"192.168.40.1","dev":"ens4"}]`
	b, err := e.DetectBaseline(context.Background())
	if err == nil || b.Interface != "eth0" || !b.HasKnownInterface() {
		t.Fatalf("switched away from addressless WAN: %+v %v", b, err)
	}
	r.hook = func(cmd string) {
		if cmd == "networkctl reconfigure eth0" {
			r.replies["ip -j -4 addr show dev eth0"] = original
		}
	}
	if err := e.RestartNetworkStack(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.calls, "\n")
	if strings.Contains(calls, "dev ens4") || !strings.Contains(calls, "dev eth0 table 200 onlink") {
		t.Fatalf("unsafe addressless recovery:\n%s", calls)
	}
}

func TestLinuxAllowedNetbirdExitIsPreservedInPolicyTables(t *testing.T) {
	e, r, b := linuxFixture(t)
	e.cfg.AllowedDefaultInterfaces = []string{"wt0"}
	r.replies["ip -4 route show default table 7120"] = "default via 100.79.0.1 dev wt0"
	if _, err := e.SurgicalCleanRoutes(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "route del default dev wt0") {
		t.Fatal("authorized exit route removed")
	}
}
