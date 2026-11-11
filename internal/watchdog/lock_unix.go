//go:build !windows

package watchdog

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type unixFileLock struct {
	file *os.File
}

func AcquireLock(lockPath string) (FileLock, error) {
	if lockPath == "" {
		return &unixFileLock{}, nil
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

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err != nil {
		_ = f.Close()
		if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("failed to acquire flock on %s: %w", lockPath, err)
	}

	return &unixFileLock{file: f}, nil
}

func (l *unixFileLock) Unlock() error {
	if l.file == nil {
		return nil
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}
