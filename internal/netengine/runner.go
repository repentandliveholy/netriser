package netengine

import (
	"context"
	"os/exec"
	"strings"
)

// CommandRunner abstracts execution of system commands across platforms.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// DefaultCommandRunner executes commands directly on the host using os/exec.
type DefaultCommandRunner struct{}

func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
