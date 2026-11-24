//go:build !windows

package install

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// installScript is scripts/install.sh (a test keeps the copy equal). In
// local mode it installs the running program instead of downloading one.
//
//go:embed install.sh
var installScript []byte

// LaunchedByDoubleClick is a Windows notion.
func LaunchedByDoubleClick() bool { return false }

// Run installs or updates NetRiser from this file without network access,
// with the same questions, migration and rollback as the online installer.
func Run(o Options) int {
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot find this program's file:", err)
		return 1
	}
	dir, err := os.MkdirTemp("", "netriser-install-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	files := map[string][]byte{"install.sh": installScript}
	for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES"} {
		files[name], _ = Legal.ReadFile("legal/" + name)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	cmd := exec.Command("/bin/sh", filepath.Join(dir, "install.sh"))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "NETRISER_LOCAL_BINARY="+self, "NETRISER_LOCAL_DOCS="+dir)
	if o.Lang != "" {
		cmd.Env = append(cmd.Env, "NETRISER_LANG="+o.Lang)
	}
	if o.Yes {
		cmd.Env = append(cmd.Env, "NETRISER_NONINTERACTIVE=1")
	}
	if o.ConfPath != "" {
		cmd.Env = append(cmd.Env, "CONF_FILE="+o.ConfPath)
	}
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "Installer could not run:", err)
		return 1
	}
	return 0
}
