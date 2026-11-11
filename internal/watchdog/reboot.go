package watchdog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RebootHistory struct {
	Timestamps []time.Time `json:"timestamps"`
}

type RebootTracker struct {
	stateDir string
	clock    Clock
}

func NewRebootTracker(stateDir string, clock Clock) *RebootTracker {
	if clock == nil {
		clock = RealClock{}
	}
	return &RebootTracker{
		stateDir: stateDir,
		clock:    clock,
	}
}

func (r *RebootTracker) historyFile() string {
	return filepath.Join(r.stateDir, "reboot_history.json")
}

func (r *RebootTracker) LoadHistory() ([]time.Time, error) {
	data, err := os.ReadFile(r.historyFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var hist RebootHistory
	if err := json.Unmarshal(data, &hist); err != nil {
		return nil, err
	}
	return hist.Timestamps, nil
}

func (r *RebootTracker) RecordReboot() error {
	timestamps, _ := r.LoadHistory()
	timestamps = append(timestamps, r.clock.Now())
	if err := os.MkdirAll(r.stateDir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(RebootHistory{Timestamps: timestamps}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.historyFile(), data, 0640)
}

func (r *RebootTracker) CanReboot(budget int, window time.Duration) (bool, string) {
	if budget <= 0 {
		return false, "reboot budget count is zero or negative"
	}
	timestamps, err := r.LoadHistory()
	if err != nil {
		return false, fmt.Sprintf("cannot read reboot history: %v", err)
	}

	cutoff := r.clock.Now().Add(-window)
	recent := 0
	for _, t := range timestamps {
		if t.After(cutoff) {
			recent++
		}
	}

	if recent >= budget {
		return false, fmt.Sprintf("reboot budget exhausted (%d reboot(s) in %v window, limit: %d)", recent, window, budget)
	}
	return true, ""
}
