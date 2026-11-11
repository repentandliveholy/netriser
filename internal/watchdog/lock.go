package watchdog

import (
	"errors"
)

var ErrAlreadyRunning = errors.New("another instance of NetRiser is already running")

type FileLock interface {
	Unlock() error
}
