package netengine

import (
	"context"
	"os"
	"path/filepath"
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
	runner.On("route", func(ctx context.Context, args []string) (string, error) {
		commandsRun = append(commandsRun, "route "+strings.Join(args, " "))
		return "", nil
	})

	baseline := Baseline{
		Interface: "en0",
		Gateway:   "192.168.1.1",
		IP:        "192.168.1.50",
	}

	session, err := StartDetachedSimulation(context.Background(), cfg, runner, baseline, 45*time.Second)
	if err != nil {
		t.Fatalf("failed to start simulation: %v", err)
	}

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

	// Test immediate rollback
	if err := session.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback error: %v", err)
	}

	// Verify rollback command was executed
	foundDelete := false
	for _, cmd := range commandsRun {
		if strings.Contains(cmd, "delete") || strings.Contains(cmd, "del") {
			foundDelete = true
			break
		}
	}
	if !foundDelete {
		t.Fatalf("expected route delete in rollback commands, got %v", commandsRun)
	}

	// Verify script is cleaned up
	scriptPath := filepath.Join(tmpDir, "safety_rollback.sh")
	if _, err := os.Stat(scriptPath); err == nil {
		t.Fatal("expected rollback script to be removed after disarm")
	}
}
