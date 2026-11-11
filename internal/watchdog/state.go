package watchdog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/netengine"
)

const CurrentStateVersion = 1

// ServiceQuarantineRecord tracks a quarantined service, its initial state, and recovery attempts.
type ServiceQuarantineRecord struct {
	Name              string    `json:"name"`
	QuarantinedAt     time.Time `json:"quarantined_at"`
	InitialState      string    `json:"initial_state"`
	Attempts          int       `json:"attempts"`
	NextRetryAfter    time.Time `json:"next_retry_after"`
	ReleaseRetryAfter time.Time `json:"release_retry_after,omitempty"`
}

// WatchdogState represents the consolidated, versioned state of the watchdog.
type WatchdogState struct {
	Version             int                       `json:"version"`
	FailCount           int                       `json:"fail_count"`
	FirstFailedAt       time.Time                 `json:"first_failed_at,omitempty"`
	LastFailedAt        time.Time                 `json:"last_failed_at,omitempty"`
	Baseline            netengine.Baseline        `json:"baseline"`
	QuarantinedServices []ServiceQuarantineRecord `json:"quarantined_services,omitempty"`
}

type StateManager struct {
	stateDir string
}

func NewStateManager(stateDir string) *StateManager {
	return &StateManager{stateDir: stateDir}
}

func (s *StateManager) stateFile() string {
	return filepath.Join(s.stateDir, "watchdog_state.json")
}

// LoadState reads and parses the versioned state, migrating legacy state files if needed.
func (s *StateManager) LoadState() (*WatchdogState, error) {
	if s.stateDir == "" {
		return &WatchdogState{Version: CurrentStateVersion}, nil
	}

	filePath := s.stateFile()
	data, err := os.ReadFile(filePath)
	if err == nil {
		var state WatchdogState
		if err := json.Unmarshal(data, &state); err != nil {
			// Corrupted state file -> create backup and return clean state
			backup := filePath + fmt.Sprintf(".corrupt.%d", time.Now().Unix())
			_ = os.Rename(filePath, backup)
			return &WatchdogState{Version: CurrentStateVersion}, fmt.Errorf("corrupted state file (backed up to %s): %w", backup, err)
		}
		return &state, nil
	}

	if os.IsNotExist(err) {
		// Migrate legacy files if present
		return s.migrateLegacyState()
	}

	return nil, err
}

// LoadStateReadOnly reads the state strictly without creating directories, writing backups, or saving migrations.
func (s *StateManager) LoadStateReadOnly() (*WatchdogState, error) {
	if s.stateDir == "" {
		return &WatchdogState{Version: CurrentStateVersion}, nil
	}

	filePath := s.stateFile()
	data, err := os.ReadFile(filePath)
	if err == nil {
		var state WatchdogState
		if err := json.Unmarshal(data, &state); err != nil {
			return &WatchdogState{Version: CurrentStateVersion}, fmt.Errorf("corrupted state file: %w", err)
		}
		return &state, nil
	}

	if os.IsNotExist(err) {
		// Read legacy files in memory without saving or mutating disk
		state := &WatchdogState{Version: CurrentStateVersion}
		if data, rErr := os.ReadFile(filepath.Join(s.stateDir, "fail_count")); rErr == nil {
			if val, pErr := strconv.Atoi(strings.TrimSpace(string(data))); pErr == nil && val >= 0 {
				state.FailCount = val
			}
		}
		if b, rErr := netengine.LoadSavedBaseline(s.stateDir); rErr == nil && b.IsValid() {
			state.Baseline = b
		}
		return state, nil
	}

	return nil, err
}

func (s *StateManager) migrateLegacyState() (*WatchdogState, error) {
	state := &WatchdogState{Version: CurrentStateVersion}

	// 1. Legacy fail_count
	if data, err := os.ReadFile(filepath.Join(s.stateDir, "fail_count")); err == nil {
		if val, pErr := strconv.Atoi(strings.TrimSpace(string(data))); pErr == nil && val >= 0 {
			state.FailCount = val
		}
	}

	// 2. Legacy baseline.json
	if b, err := netengine.LoadSavedBaseline(s.stateDir); err == nil && b.IsValid() {
		state.Baseline = b
	}

	// 3. Legacy quarantined_services
	if data, err := os.ReadFile(filepath.Join(s.stateDir, "quarantined_services")); err == nil {
		words := strings.Fields(string(data))
		retryAfter := time.Time{}
		if rData, rErr := os.ReadFile(filepath.Join(s.stateDir, "quarantine_retry_after")); rErr == nil {
			if sec, sErr := strconv.ParseInt(strings.TrimSpace(string(rData)), 10, 64); sErr == nil {
				retryAfter = time.Unix(sec, 0)
			}
		}

		for _, w := range words {
			w = strings.Trim(w, ",:; \t\n\r")
			if w != "" {
				state.QuarantinedServices = append(state.QuarantinedServices, ServiceQuarantineRecord{
					Name:           w,
					QuarantinedAt:  time.Now(),
					InitialState:   "active",
					Attempts:       1,
					NextRetryAfter: retryAfter,
				})
			}
		}
	}

	// Save migrated consolidated state
	_ = s.SaveState(state)
	return state, nil
}

// SaveState atomically writes the state using a temp file and rename.
func (s *StateManager) SaveState(state *WatchdogState) error {
	if s.stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(s.stateDir, 0750); err != nil {
		return fmt.Errorf("failed to create state dir: %w", err)
	}

	state.Version = CurrentStateVersion
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	target := s.stateFile()
	tmpFile := fmt.Sprintf("%s.tmp.%d", target, time.Now().UnixNano())

	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to write temp state file: %w", err)
	}

	// Atomic replace
	if err := os.Rename(tmpFile, target); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to atomic replace state file: %w", err)
	}

	return nil
}
