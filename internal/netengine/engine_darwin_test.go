//go:build darwin

package netengine

import (
	"context"
	"errors"
	"github.com/repentandliveholy/netriser/internal/config"
	"strings"
	"testing"
)

func TestFakeRunnerPartialSuccess(t *testing.T) {
	runner := NewScriptedRunner()
	runner.On("netstat -rn -f inet", func(ctx context.Context, args []string) (string, error) {
		return `Routing tables
Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGSc           en0
0/1                10.200.0.1         UGSc          utun3
128.0/1            10.200.0.1         UGSc          utun3`, nil
	})

	// One delete succeeds, one fails
	runner.On("route -n delete 0/1", func(ctx context.Context, args []string) (string, error) {
		return "delete net 0/1", nil
	})
	runner.On("route -n delete 128.0/1", func(ctx context.Context, args []string) (string, error) {
		return "route: route not found", errors.New("route not found")
	})

	cfg := config.DefaultConfig()
	cfg.AllowVPNBypass = true // utun is a generic tunnel (VPN kind)
	engine := NewEngineWithRunner(cfg, runner)

	actions, err := engine.SurgicalCleanRoutes(context.Background(), Baseline{
		Interface: "en0",
		Gateway:   "192.168.1.1",
		IP:        "192.168.1.50",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundSuccess := false
	foundFailed := false
	for _, act := range actions {
		if act.Type == ActionCleanRoute && strings.Contains(act.Target, "0/1") && act.Status == ActionExecuted {
			foundSuccess = true
		}
		if act.Type == ActionCleanRoute && strings.Contains(act.Target, "128.0/1") && act.Status == ActionFailed {
			foundFailed = true
		}
	}

	if !foundSuccess {
		t.Errorf("expected executed status for 0/1 route deletion")
	}
	if !foundFailed {
		t.Errorf("expected failed status for 128.0/1 route deletion")
	}
}

func TestDarwinVPNRoutesPreservedWithoutBypass(t *testing.T) {
	runner := NewScriptedRunner()
	runner.On("netstat -rn -f inet", func(ctx context.Context, args []string) (string, error) {
		return `Routing tables
Internet:
Destination        Gateway            Flags        Netif Expire
default            10.8.0.1           UGSc          utun3
default            192.168.1.1        UGSc           en0
0/1                10.200.0.1         UGSc          utun3
128.0/1            10.200.0.1         UGSc          utun3`, nil
	})
	var deleted []string
	for _, half := range []string{"0/1", "128.0/1", "0.0.0.0/1", "128.0.0.0/1", "default", "default 10.8.0.1"} {
		half := half
		runner.On("route -n delete "+half, func(ctx context.Context, args []string) (string, error) {
			deleted = append(deleted, half)
			return "", nil
		})
	}
	engine := NewEngineWithRunner(config.DefaultConfig(), runner)
	b := Baseline{Interface: "en0", Gateway: "192.168.1.1", IP: "192.168.1.50"}
	if _, err := engine.SurgicalCleanRoutes(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	acts, err := engine.QuarantineMeshServices(context.Background())
	if err != nil || len(acts) != 1 || acts[0].Status != ActionSkipped {
		t.Fatalf("quarantine without evidence: %+v %v", acts, err)
	}
	if len(deleted) != 0 {
		t.Fatalf("VPN routes deleted without allow_vpn_bypass: %v", deleted)
	}
}
