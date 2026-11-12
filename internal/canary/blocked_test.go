package canary

import (
	"context"
	"errors"
	"testing"
)

func TestProbesBlocked(t *testing.T) {
	resolves := func(ctx context.Context, name string) ([]string, error) { return []string{"192.0.2.1"}, nil }
	fails := func(ctx context.Context, name string) ([]string, error) { return nil, errors.New("no route") }
	answers := func(ctx context.Context, host string) error { return nil }
	silent := func(ctx context.Context, host string) error { return errors.New("no reply") }

	cases := []struct {
		name    string
		gateway string
		lookup  func(context.Context, string) ([]string, error)
		ping    func(context.Context, string) error
		noDNS   bool
		want    bool
	}{
		{"dns and router answer", "192.168.1.1", resolves, answers, false, true},
		{"dns fails", "192.168.1.1", fails, answers, false, false},
		{"router silent", "192.168.1.1", resolves, silent, false, false},
		{"gateway unknown", "", resolves, answers, false, false},
		{"no dns canaries", "192.168.1.1", resolves, answers, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dnsChecker(t)
			if tc.noDNS {
				c.cfg.DNSCanaries = nil
			}
			c.lookupHost, c.pingHost = tc.lookup, tc.ping
			got, why := c.ProbesBlocked(context.Background(), tc.gateway)
			if got != tc.want {
				t.Fatalf("ProbesBlocked = %v (%q), want %v", got, why, tc.want)
			}
			if got && why == "" {
				t.Fatal("missing explanation")
			}
		})
	}
}
