package netengine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

func TestDetachedSimulationLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.StateDir = tmpDir

	runner := NewScriptedRunner()
	commandsRun := []string{}
	for _, name := range []string{"route", "route.exe", "ip"} {
		name := name
		runner.On(name, func(ctx context.Context, args []string) (string, error) {
			commandsRun = append(commandsRun, name+" "+strings.Join(args, " "))
			return "", nil
		})
	}

	baseline := Baseline{
		Interface: "en0",
		Gateway:   "192.168.1.1",
		IP:        "192.168.1.50",
	}

	session, err := StartDetachedSimulation(context.Background(), cfg, runner, baseline, 45*time.Second)
	if err != nil {
		t.Fatalf("failed to start simulation: %v", err)
	}

	t.Cleanup(func() { _ = session.Disarm() })

	// Verify that rollback script was created on disk
	entries, _ := os.ReadDir(tmpDir)
	foundScript := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "safety_rollback") {
			foundScript = true
			break
		}
	}
	if !foundScript {
		t.Fatal("expected safety rollback script to be created")
	}

	// Test immediate rollback separately from the route injection command.
	commandsRun = nil
	if err := session.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback error: %v", err)
	}

	var want []string
	switch runtime.GOOS {
	case "darwin":
		want = []string{"route -n delete default 198.51.100.254", "route -n add default 192.168.1.1 -iface en0"}
	case "windows":
		want = []string{"route.exe delete 0.0.0.0 MASK 0.0.0.0 198.51.100.254", "route.exe add 0.0.0.0 MASK 0.0.0.0 192.168.1.1 METRIC 10"}
	default:
		want = []string{"ip route del default via 198.51.100.254", "ip route replace default via 192.168.1.1 dev en0"}
	}
	if !reflect.DeepEqual(commandsRun, want) {
		t.Fatalf("rollback commands = %v, want %v", commandsRun, want)
	}

	// Verify script is cleaned up
	scriptName := "safety_rollback.sh"
	if runtime.GOOS == "windows" {
		scriptName = "safety_rollback.cmd"
	}
	scriptPath := filepath.Join(tmpDir, scriptName)
	if _, err := os.Stat(scriptPath); err == nil {
		t.Fatal("expected rollback script to be removed after disarm")
	}
}
