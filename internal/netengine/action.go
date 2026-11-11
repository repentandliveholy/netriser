package netengine

import "fmt"

// ActionStatus represents the discrete execution state of a remediation action.
type ActionStatus string

const (
	ActionExecuted  ActionStatus = "executed"        // action was successfully performed
	ActionNotNeeded ActionStatus = "not_needed"      // action was evaluated but determined unnecessary
	ActionSkipped   ActionStatus = "skipped"         // action was skipped due to preconditions or budget
	ActionFailed    ActionStatus = "failed"          // action failed during execution
	ActionPartial   ActionStatus = "partial_success" // action partially succeeded
)

// ActionType classifies the remediation operation.
type ActionType string

const (
	ActionCleanRoute        ActionType = "clean_route"
	ActionRestoreRoute      ActionType = "restore_route"
	ActionQuarantineService ActionType = "quarantine_service"
	ActionRestoreService    ActionType = "restore_service"
	ActionRestartStack      ActionType = "restart_stack"
	ActionReboot            ActionType = "reboot"
	ActionApplyPolicy       ActionType = "apply_policy"
	ActionRemovePolicy      ActionType = "remove_policy"
	ActionRestoreDNS        ActionType = "restore_dns"
)

// ActionResult records structured details and outcomes of remediation actions.
type ActionResult struct {
	Type        ActionType   `json:"type"`
	Target      string       `json:"target"`
	Status      ActionStatus `json:"status"`
	StateBefore string       `json:"state_before,omitempty"`
	StateAfter  string       `json:"state_after,omitempty"`
	Error       string       `json:"error,omitempty"`
	Description string       `json:"description,omitempty"`
}

// String provides a human-readable summary of the action result.
func (a ActionResult) String() string {
	if a.Error != "" {
		if a.Description != "" {
			return fmt.Sprintf("[%s:%s] %s (%s, err=%s)", a.Type, a.Status, a.Description, a.Target, a.Error)
		}
		return fmt.Sprintf("[%s:%s] %s (err=%s)", a.Type, a.Status, a.Target, a.Error)
	}
	if a.Description != "" {
		return fmt.Sprintf("[%s:%s] %s (%s)", a.Type, a.Status, a.Description, a.Target)
	}
	return fmt.Sprintf("[%s:%s] %s", a.Type, a.Status, a.Target)
}
