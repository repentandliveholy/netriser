//go:build windows

package watchdog

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type windowsFileLock struct {
	file *os.File
}

func AcquireLock(lockPath string) (FileLock, error) {
	if lockPath == "" {
		return &windowsFileLock{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		if !os.IsPermission(err) {
			return nil, err
		}
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}

	var ol windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	if err != nil {
		_ = f.Close()
		if err == windows.ERROR_LOCK_VIOLATION {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("failed to acquire windows lock on %s: %w", lockPath, err)
	}

	return &windowsFileLock{file: f}, nil
}

func (l *windowsFileLock) Unlock() error {
	if l.file == nil {
		return nil
	}
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &ol)
	err := l.file.Close()
	l.file = nil
	return err
}
