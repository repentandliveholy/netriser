//go:build !linux && !windows && !darwin

package netengine

import (
	"context"
	"fmt"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

type StubEngine struct {
	cfg    *config.Config
	runner CommandRunner
}

func NewEngine(cfg *config.Config) NetworkEngine {
	return NewEngineWithRunner(cfg, nil)
}

func NewEngineWithRunner(cfg *config.Config, runner CommandRunner) NetworkEngine {
	ConfigureOverlays(cfg)
	if runner == nil {
		runner = &DefaultCommandRunner{}
	}
	return &StubEngine{cfg: cfg, runner: runner}
}

func (e *StubEngine) DetectBaseline(ctx context.Context) (Baseline, error) {
	return Baseline{}, fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) ApplyPolicyRouting(ctx context.Context, b Baseline) error {
	return fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) RemovePolicyRouting(ctx context.Context, b Baseline) error {
	return fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) SurgicalCleanRoutes(ctx context.Context, b Baseline) ([]ActionResult, error) {
	return nil, fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) QuarantineMeshServices(ctx context.Context) ([]ActionResult, error) {
	return nil, fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) RestoreMeshServices(ctx context.Context, services []string) ([]ActionResult, error) {
	return nil, fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) RestartNetworkStack(ctx context.Context, b Baseline) error {
	return fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) EmergencyReboot(ctx context.Context, reason string) error {
	return fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) SimulateHijack(ctx context.Context, b Baseline, rollbackDuration time.Duration) (func(), error) {
	return nil, fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) SimulateHijackSession(ctx context.Context, b Baseline, rollbackDuration time.Duration) (SimulationSession, error) {
	return nil, fmt.Errorf("unsupported OS platform")
}

func (e *StubEngine) DumpDiagnostics(ctx context.Context, b Baseline) (string, error) {
	return "unsupported OS platform", nil
}
