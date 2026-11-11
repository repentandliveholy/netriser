//go:build windows

package updater

import (
	"fmt"
	"os"
	"time"
)

func replaceExecutable(targetPath, tempPath string) error {
	oldPath := targetPath + ".old"
	// Best effort cleanup of any leftover previous backup
	_ = os.Remove(oldPath)

	// In Windows, a running executable cannot be overwritten or deleted,
	// but it CAN be renamed while open!
	if err := os.Rename(targetPath, oldPath); err != nil {
		return fmt.Errorf("failed to move running executable to %s: %w", oldPath, err)
	}

	// Move the newly downloaded executable into place
	if err := os.Rename(tempPath, targetPath); err != nil {
		// Attempt rollback if placing new executable fails
		_ = os.Rename(oldPath, targetPath)
		return fmt.Errorf("failed to move new executable into %s: %w", targetPath, err)
	}

	// Try removing old file (will succeed once locks are released or on next run)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = os.Remove(oldPath)
	}()

	return nil
}
