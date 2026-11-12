//go:build !windows

package term

import "os"

func enableANSI(*os.File) bool { return true }
