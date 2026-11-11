package watchdog

import (
	"fmt"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
)

type EscalationDecision struct {
	Stage         int
	Reason        string
	ActionAllowed bool
	ActionType    netengine.ActionType
	SkipReason    string
}

// DecideEscalation calculates the appropriate escalation stage and decides whether
// remediation action is authorized given failure count, thresholds, permissions, baseline,
// startup grace, and reboot budget.
func DecideEscalation(
	failCount int,
	cfg *config.Config,
	baseline netengine.Baseline,
	rebootAllowed bool,
	rebootBudgetReason string,
	inStartupGrace bool,
) EscalationDecision {
	if cfg.ObservationMode {
		return EscalationDecision{
			Stage:         0,
			Reason:        fmt.Sprintf("observation mode enabled; failure count %d recorded", failCount),
			ActionAllowed: false,
			ActionType:    "",
			SkipReason:    "observation mode enabled",
		}
	}

	// If failure count is below Stage 1 threshold, perform observation only
	if failCount < cfg.FailThresholdStage1 {
		return EscalationDecision{
			Stage:         0,
			Reason:        fmt.Sprintf("failure count %d below Stage 1 threshold %d; observing", failCount, cfg.FailThresholdStage1),
			ActionAllowed: false,
			ActionType:    "",
			SkipReason:    "threshold not reached",
		}
	}

	// Progressive Escalation Ladder
	switch {
	case failCount >= cfg.FailThresholdStage4Reboot:
		if !cfg.EnableReboot {
			return EscalationDecision{
				Stage:         4,
				Reason:        fmt.Sprintf("Stage 4 reached at failure count %d, but reboot is disabled", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionReboot,
				SkipReason:    "reboot disabled in configuration",
			}
		}
		if inStartupGrace {
			return EscalationDecision{
				Stage:         4,
				Reason:        fmt.Sprintf("Stage 4 reached at failure count %d, but host is within startup grace period", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionReboot,
				SkipReason:    "startup grace period active",
			}
		}
		if !baseline.IsValid() {
			return EscalationDecision{
				Stage:         4,
				Reason:        fmt.Sprintf("Stage 4 reached at failure count %d, but baseline is invalid/unknown", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionReboot,
				SkipReason:    "invalid baseline",
			}
		}
		if !rebootAllowed {
			return EscalationDecision{
				Stage:         4,
				Reason:        fmt.Sprintf("Stage 4 reached at failure count %d, but emergency reboot is not yet allowed: %s", failCount, rebootBudgetReason),
				ActionAllowed: false,
				ActionType:    netengine.ActionReboot,
				SkipReason:    rebootBudgetReason,
			}
		}
		return EscalationDecision{
			Stage:         4,
			Reason:        fmt.Sprintf("Stage 4 reached at failure count %d: triggering emergency host reboot", failCount),
			ActionAllowed: true,
			ActionType:    netengine.ActionReboot,
		}

	case failCount >= cfg.FailThresholdStage3:
		if !cfg.AllowNetworkRestart {
			return EscalationDecision{
				Stage:         3,
				Reason:        fmt.Sprintf("Stage 3 reached at failure count %d, but network restart is disabled", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionRestartStack,
				SkipReason:    "network restart disabled in configuration",
			}
		}
		if !baseline.IsValid() && !baseline.HasKnownInterface() {
			return EscalationDecision{
				Stage:         3,
				Reason:        fmt.Sprintf("Stage 3 reached at failure count %d, but baseline is invalid", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionRestartStack,
				SkipReason:    "invalid baseline",
			}
		}
		return EscalationDecision{
			Stage:         3,
			Reason:        fmt.Sprintf("Stage 3 reached at failure count %d: restarting network stack", failCount),
			ActionAllowed: true,
			ActionType:    netengine.ActionRestartStack,
		}

	case failCount >= cfg.FailThresholdStage2:
		if !baseline.IsValid() {
			return EscalationDecision{Stage: 2, Reason: "Physical baseline unknown; preserving overlay access", ActionAllowed: false, ActionType: netengine.ActionQuarantineService, SkipReason: "invalid baseline"}
		}
		if !cfg.AllowServiceQuarantine {
			return EscalationDecision{
				Stage:         2,
				Reason:        fmt.Sprintf("Stage 2 reached at failure count %d, but service quarantine is disabled", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionQuarantineService,
				SkipReason:    "service quarantine disabled in configuration",
			}
		}
		return EscalationDecision{
			Stage:         2,
			Reason:        fmt.Sprintf("Stage 2 reached at failure count %d: quarantining suspect mesh services", failCount),
			ActionAllowed: true,
			ActionType:    netengine.ActionQuarantineService,
		}

	default: // Stage 1 (failCount >= FailThresholdStage1)
		if !cfg.AllowRouteSanitation {
			return EscalationDecision{
				Stage:         1,
				Reason:        fmt.Sprintf("Stage 1 reached at failure count %d, but route sanitation is disabled", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionCleanRoute,
				SkipReason:    "route sanitation disabled in configuration",
			}
		}
		if !baseline.IsValid() {
			return EscalationDecision{
				Stage:         1,
				Reason:        fmt.Sprintf("Stage 1 reached at failure count %d, but baseline is invalid", failCount),
				ActionAllowed: false,
				ActionType:    netengine.ActionCleanRoute,
				SkipReason:    "invalid baseline",
			}
		}
		return EscalationDecision{
			Stage:         1,
			Reason:        fmt.Sprintf("Stage 1 reached at failure count %d: executing surgical route sanitation", failCount),
			ActionAllowed: true,
			ActionType:    netengine.ActionCleanRoute,
		}
	}
}
