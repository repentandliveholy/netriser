package netengine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Regex matching virtual/local non-physical interfaces to ignore
var IgnoredIfaceRegex = regexp.MustCompile(`^(lo|docker[0-9]*|br-[a-f0-9]+|veth[a-f0-9]+|virbr[0-9]+|cni[0-9]+|flannel.*)`)

type BaselineSource string

const (
	BaselineSourceConfig BaselineSource = "config"
	BaselineSourceAuto   BaselineSource = "auto_detected"
	BaselineSourceCached BaselineSource = "cached"
)

// Baseline represents detected or configured physical network management parameters.
type Baseline struct {
	Interface     string         `json:"interface"`
	Gateway       string         `json:"gateway"`
	IP            string         `json:"ip"`
	SubnetMask    string         `json:"subnet_mask,omitempty"`
	Source        BaselineSource `json:"source,omitempty"`
	DetectedAt    time.Time      `json:"detected_at"`
	LastConfirmed time.Time      `json:"last_confirmed,omitempty"`
}

// String provides a human-readable baseline summary.
func (b Baseline) String() string {
	return fmt.Sprintf("Interface=%s IP=%s Gateway=%s Source=%s", b.Interface, b.IP, b.Gateway, b.Source)
}

// IsValid checks whether baseline has required interface and IP.
func (b Baseline) IsValid() bool {
	return b.Interface != "" && b.IP != ""
}

// HasKnownInterface allows the OS manager to recover a configured/cached WAN
// even when its address was lost. It never authorizes route or policy changes.
func (b Baseline) HasKnownInterface() bool {
	return b.Interface != "" && !IsIgnoredInterface(b.Interface) && (b.Source == BaselineSourceConfig || b.Source == BaselineSourceCached)
}

// NetworkEngine is the platform-specific OS network interface.
type DNSRecoveryEngine interface {
	CaptureDNSBaseline(ctx context.Context) error
	RestoreDNS(ctx context.Context) ([]ActionResult, error)
}

type NetworkEngine interface {
	// DetectBaseline discovers physical interface, gateway, and primary IP.
	DetectBaseline(ctx context.Context) (Baseline, error)

	// ApplyPolicyRouting enforces management routing rules (e.g. Table 200 on Linux).
	ApplyPolicyRouting(ctx context.Context, b Baseline) error

	// RemovePolicyRouting cleans up custom policy routing rules.
	RemovePolicyRouting(ctx context.Context, b Baseline) error

	// SurgicalCleanRoutes removes rogue default / /1 routes on mesh interfaces and restores physical default gateway.
	SurgicalCleanRoutes(ctx context.Context, b Baseline) ([]ActionResult, error)

	// QuarantineMeshServices temporarily stops overlay services and brings down virtual interfaces.
	QuarantineMeshServices(ctx context.Context) ([]ActionResult, error)

	// RestoreMeshServices attempts to restart quarantined overlay services after network recovers.
	RestoreMeshServices(ctx context.Context, services []string) ([]ActionResult, error)

	// RestartNetworkStack restarts the host network daemon/adapter.
	RestartNetworkStack(ctx context.Context, b Baseline) error

	// EmergencyReboot initiates OS reboot as ultimate fail-safe.
	EmergencyReboot(ctx context.Context, reason string) error

	// SimulateHijack injects a dummy rogue default route with a guaranteed background rollback timer.
	SimulateHijack(ctx context.Context, b Baseline, rollbackDuration time.Duration) (cancelFn func(), err error)

	// SimulateHijackSession injects a dummy rogue default route and returns an independent SimulationSession.
	SimulateHijackSession(ctx context.Context, b Baseline, rollbackDuration time.Duration) (SimulationSession, error)

	// DumpDiagnostics returns a comprehensive text report of routing tables, interfaces, and services.
	DumpDiagnostics(ctx context.Context, b Baseline) (string, error)
}

// SaveBaseline writes baseline to StateDir/baseline.json.
func SaveBaseline(stateDir string, b Baseline) error {
	if stateDir == "" || !b.IsValid() {
		return nil
	}
	if err := os.MkdirAll(stateDir, 0750); err != nil {
		return err
	}
	file := filepath.Join(stateDir, "baseline.json")
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".baseline-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}

// LoadSavedBaseline loads previously cached baseline from StateDir/baseline.json.
func LoadSavedBaseline(stateDir string) (Baseline, error) {
	var b Baseline
	if stateDir == "" {
		return b, os.ErrNotExist
	}
	file := filepath.Join(stateDir, "baseline.json")
	data, err := os.ReadFile(file)
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(data, &b)
	return b, err
}

// IsMeshInterface reports whether an interface belongs to any recognised VPN
// or overlay (built-in or configured), see overlays.go.
func IsMeshInterface(name string) bool {
	_, ok := ClassifyUnix(name)
	return ok
}

// Helper to determine if interface should be ignored when looking for physical adapters.
func IsIgnoredInterface(name string) bool {
	return IgnoredIfaceRegex.MatchString(name) || IsMeshInterface(name)
}
