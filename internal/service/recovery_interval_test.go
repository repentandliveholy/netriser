package service

import (
	"errors"
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

func TestOutageCadenceAndReturnToNormalMonitoring(t *testing.T) {
	cfg := config.DefaultConfig()
	for _, tc := range []struct {
		name   string
		report *watchdog.CheckReport
		err    error
		want   time.Duration
	}{
		{"healthy", &watchdog.CheckReport{Healthy: true}, nil, time.Minute},
		{"outage", &watchdog.CheckReport{FailCount: 1}, nil, 15 * time.Second},
		{"later stage", &watchdog.CheckReport{FailCount: 4}, nil, 15 * time.Second},
		{"restored", &watchdog.CheckReport{Healthy: true, Remediated: true}, nil, time.Minute},
		{"DNS only", &watchdog.CheckReport{FailCount: 0}, nil, time.Minute},
		{"lock or state error", nil, errors.New("unavailable"), time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextCheckDelay(cfg, tc.report, tc.err); got != tc.want {
				t.Fatalf("delay=%v want %v", got, tc.want)
			}
		})
	}
}
