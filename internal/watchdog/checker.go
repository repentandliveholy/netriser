package watchdog

import (
	"context"

	"github.com/repentandliveholy/netriser/internal/canary"
)

// ConnectivityChecker abstracts network health probing.
type ConnectivityChecker interface {
	CheckFast(ctx context.Context) canary.HealthResult
	CheckDetailed(ctx context.Context) canary.HealthResult
}

// probeFilterChecker is implemented by checkers that can tell blocked
// internet probes from a missing internet (canary.Checker does).
type probeFilterChecker interface {
	ProbesBlocked(ctx context.Context, gateway string) (bool, string)
}
