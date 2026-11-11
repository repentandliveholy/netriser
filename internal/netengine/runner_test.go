package netengine

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type ScriptedRunner struct {
	handlers map[string]func(ctx context.Context, args []string) (string, error)
}

func NewScriptedRunner() *ScriptedRunner {
	return &ScriptedRunner{
		handlers: make(map[string]func(ctx context.Context, args []string) (string, error)),
	}
}

func (r *ScriptedRunner) On(cmd string, handler func(ctx context.Context, args []string) (string, error)) {
	r.handlers[cmd] = handler
}

func (r *ScriptedRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	for pattern, handler := range r.handlers {
		if strings.HasPrefix(key, pattern) {
			return handler(ctx, args)
		}
	}
	return "", nil
}

func TestFakeRunnerTimeout(t *testing.T) {
	runner := NewScriptedRunner()
	runner.On("route -n get default", func(ctx context.Context, args []string) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
			return "", nil
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := runner.Run(ctx, "route", "-n", "get", "default")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestFakeRunnerPermissionDenied(t *testing.T) {
	runner := NewScriptedRunner()
	runner.On("route -n delete", func(ctx context.Context, args []string) (string, error) {
		return "route: must be root to alter routing table", os.ErrPermission
	})

	_, err := runner.Run(context.Background(), "route", "-n", "delete", "0/1")
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected permission error, got %v", err)
	}
}
