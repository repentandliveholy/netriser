//go:build !windows

package updater

import (
	"fmt"
	"os"
)

func replaceExecutable(targetPath, tempPath string) error {
	if err := os.Chmod(tempPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions on %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, targetPath); err != nil {
		return fmt.Errorf("failed to atomically replace binary %s: %w", targetPath, err)
	}
	return nil
}
