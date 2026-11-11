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
