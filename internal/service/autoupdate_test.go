package service

import (
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

func TestAutomaticUpdatesWaitForHealthyNetworkAndRespectSwitch(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                          string
		enabled, healthy, observation bool
		uptime, elapsed               time.Duration
		due                           bool
	}{
		{"default enabled and due", true, true, false, time.Hour, 7 * time.Hour, true},
		{"off", false, true, false, time.Hour, 7 * time.Hour, false},
		{"outage", true, false, false, time.Hour, 7 * time.Hour, false},
		{"startup", true, true, false, 4 * time.Minute, 7 * time.Hour, false},
		{"observation", true, true, true, time.Hour, 7 * time.Hour, false},
		{"not due", true, true, false, time.Hour, time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AutoUpdate = tc.enabled
			cfg.ObservationMode = tc.observation
			got := automaticDue(cfg, tc.healthy, now.Add(-tc.uptime), now.Add(-tc.elapsed), now)
			if got != tc.due {
				t.Fatalf("due=%t want %t", got, tc.due)
			}
		})
	}
	cfg := config.DefaultConfig()
	if !automaticDue(cfg, true, now.Add(-5*time.Minute), time.Time{}, now) {
		t.Fatal("first check never scheduled")
	}
	cfg.AutoUpdateIntervalSec = 60
	if !automaticDue(cfg, true, now.Add(-time.Hour), now.Add(-time.Minute), now) {
		t.Fatal("custom interval ignored")
	}
}
