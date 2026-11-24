//go:build !windows

package install

import (
	"fmt"
	"os"

	"github.com/repentandliveholy/netriser/internal/i18n"
)

// LaunchedByDoubleClick is a Windows notion.
func LaunchedByDoubleClick() bool { return false }

// Run explains how to install on this system.
func Run(o Options) int {
	lang := o.Lang
	if lang == "" {
		lang = i18n.FromEnvironment()
	}
	fmt.Fprintln(os.Stderr, i18n.T(lang, "inst_other_os"))
	return 1
}
