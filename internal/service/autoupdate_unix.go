//go:build !windows

package service

import (
	"os/exec"
	"syscall"
)

// Keep the updater alive when launchd terminates the daemon's process group.
func detachUpdateHelper(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
