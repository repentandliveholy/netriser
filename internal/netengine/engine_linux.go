//go:build linux

package netengine

import "github.com/repentandliveholy/netriser/internal/config"

func NewEngine(cfg *config.Config) NetworkEngine {
	return NewEngineWithRunner(cfg, nil)
}

func NewEngineWithRunner(cfg *config.Config, runner CommandRunner) NetworkEngine {
	ConfigureOverlays(cfg)
	if runner == nil {
		runner = &DefaultCommandRunner{}
	}
	return &LinuxEngine{cfg: cfg, runner: runner}
}
