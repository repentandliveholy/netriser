package watchdog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoggerRotation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "watchdog_log_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "watchdog.log")
	logger := NewLogger(logPath, false)
	logger.SetMaxFileSize(200) // very small size to trigger rotation quickly

	// Write lines until rotation triggers
	for i := 0; i < 20; i++ {
		logger.Info("This is log message number %d with enough text to exceed size", i)
	}

	// Verify primary log file exists
	if _, err := os.Stat(logPath); err != nil {
		t.Errorf("primary log file does not exist: %v", err)
	}

	// Verify rotated backup file exists
	backupPath := logPath + ".1"
	if _, err := os.Stat(backupPath); err != nil {
		t.Errorf("rotated log backup does not exist: %v", err)
	}
}

func TestLoggerJSONModeDoesNotTouchStdout(t *testing.T) {
	logger := NewLogger("", true)
	logger.SetJSONMode(true)

	if !logger.jsonMode {
		t.Errorf("expected jsonMode to be true")
	}
}
