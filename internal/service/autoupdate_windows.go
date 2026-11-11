package service

import "os/exec"

// Child processes survive their parent's service stop on Windows.
func detachUpdateHelper(cmd *exec.Cmd) {}
