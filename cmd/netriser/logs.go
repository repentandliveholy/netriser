package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultLogLines = 50

// recentLogLines returns the last n lines of the log, continuing into the
// rotated file (path + ".1") when the current one is shorter than n.
func recentLogLines(path string, n int) ([]string, error) {
	var lines []string
	found := false
	for _, p := range []string{path + ".1", path} {
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		found = true
		for _, l := range strings.Split(strings.TrimRight(string(data), "\r\n"), "\n") {
			if l = strings.TrimRight(l, "\r"); l != "" {
				lines = append(lines, l)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("log file %s does not exist yet: %w", path, os.ErrNotExist)
	}
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// followLog streams lines appended to the log until ctx ends. The file is
// reopened on every poll and never held open, so the service can still rotate
// it (Windows refuses to rename a file another process has open). Rotation or
// truncation is detected by the file shrinking or being replaced.
func followLog(ctx context.Context, path string, w io.Writer, poll time.Duration) error {
	var offset int64
	var last os.FileInfo
	if fi, err := os.Stat(path); err == nil {
		offset, last = fi.Size(), fi
	}
	var partial []byte
	for {
		fi, err := os.Stat(path)
		switch {
		case err == nil:
			if last != nil && (!os.SameFile(last, fi) || fi.Size() < offset) {
				offset = 0
			}
			last = fi
			if fi.Size() > offset {
				chunk, n, rerr := readFrom(path, offset)
				if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
					return rerr
				}
				offset += n
				partial = append(partial, chunk...)
				if i := bytes.LastIndexByte(partial, '\n'); i >= 0 {
					if _, werr := w.Write(partial[:i+1]); werr != nil {
						return werr
					}
					partial = append([]byte{}, partial[i+1:]...)
				}
			}
		case errors.Is(err, os.ErrNotExist):
			// Between rotation steps, or before the service's first write.
			last, offset = nil, 0
		default:
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(poll):
		}
	}
}

func readFrom(path string, offset int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, 0, err
	}
	data, err := io.ReadAll(f)
	return data, int64(len(data)), err
}

// runLogs prints recent log lines: `nr logs [N|all]`.
func runLogs(path string, args []string) int {
	n := defaultLogLines
	if len(args) > 0 {
		if args[0] == "all" {
			n = 0
		} else if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		} else {
			fmt.Fprintf(os.Stderr, "Usage: netriser logs [number of lines|all] (default %d)\n", defaultLogLines)
			return 2
		}
	}
	lines, err := recentLogLines(path, n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read log: %v\n", err)
		return 1
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	return 0
}

// runLive shows the last lines for context, then streams new ones until Ctrl+C.
func runLive(path string) int {
	if lines, err := recentLogLines(path, 10); err == nil {
		for _, l := range lines {
			fmt.Println(l)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "Cannot read log: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "-- following %s (Ctrl+C to stop) --\n", path)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := followLog(ctx, path, os.Stdout, 500*time.Millisecond); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot follow log: %v\n", err)
		return 1
	}
	return 0
}
