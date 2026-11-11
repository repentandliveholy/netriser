package watchdog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const DefaultMaxLogBytes = 5 * 1024 * 1024 // 5 MB

type Logger struct {
	mu          sync.Mutex
	logPath     string
	verbose     bool
	jsonMode    bool
	maxFileSize int64
}

func NewLogger(logPath string, verbose bool) *Logger {
	return &Logger{
		logPath:     logPath,
		verbose:     verbose,
		maxFileSize: DefaultMaxLogBytes,
	}
}

// SetJSONMode directs console log output to Stderr when JSON mode is enabled,
// ensuring Stdout contains strictly parseable JSON data.
func (l *Logger) SetJSONMode(jsonMode bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.jsonMode = jsonMode
}

// SetMaxFileSize overrides the default log rotation size threshold.
func (l *Logger) SetMaxFileSize(bytes int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if bytes > 0 {
		l.maxFileSize = bytes
	}
}

func (l *Logger) Log(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] [%s] %s\n", ts, level, msg)

	if l.verbose {
		targetWriter := io.Writer(os.Stdout)
		if l.jsonMode {
			targetWriter = os.Stderr
		}
		_, _ = io.WriteString(targetWriter, line)
	}

	if l.logPath != "" {
		l.writeWithRotation(line)
	}
}

func (l *Logger) writeWithRotation(line string) {
	// Check rotation threshold
	if fi, err := os.Stat(l.logPath); err == nil {
		if fi.Size()+int64(len(line)) > l.maxFileSize {
			backup := l.logPath + ".1"
			_ = os.Remove(backup)
			_ = os.Rename(l.logPath, backup)
		}
	}

	dir := filepath.Dir(l.logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog logger: failed to create log directory %s: %v\n", dir, err)
		return
	}

	f, err := os.OpenFile(l.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "watchdog logger: failed to open log file %s: %v\n", l.logPath, err)
		return
	}
	defer f.Close()

	if _, err := io.WriteString(f, line); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog logger: failed to write to log file %s: %v\n", l.logPath, err)
	}
}

func (l *Logger) Info(format string, args ...any) {
	l.Log("INFO", format, args...)
}

func (l *Logger) Warn(format string, args ...any) {
	l.Log("WARN", format, args...)
}

func (l *Logger) Error(format string, args ...any) {
	l.Log("ERROR", format, args...)
}

func (l *Logger) Recovery(format string, args ...any) {
	l.Log("RECOVERY", format, args...)
}
