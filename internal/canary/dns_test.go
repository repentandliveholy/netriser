package canary

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

func dnsChecker(t *testing.T) *Checker {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.CanaryTargets = nil
	cfg.HTTPFallbackURL = "http://transport.test"
	cfg.ProbeTimeoutSec = 1
	c := NewChecker(cfg)
	c.SetHTTPClient(&http.Client{Transport: mockRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})})
	return c
}

func TestDNSFailureCannotHideBehindHealthyIP(t *testing.T) {
	for _, detailed := range []bool{false, true} {
		c := dnsChecker(t)
		c.lookupHost = func(ctx context.Context, name string) ([]string, error) {
			if ctx.Err() != nil {
				t.Error("IP winner cancelled the DNS context")
			}
			return nil, errors.New("system resolver unavailable")
		}
		var result HealthResult
		if detailed {
			result = c.CheckDetailed(context.Background())
		} else {
			result = c.CheckFast(context.Background())
		}
		if result.Healthy || !result.InternetHealthy || !result.DNSOnlyFailure() {
			t.Fatalf("DNS failure hidden: %+v", result)
		}
	}
}

func TestDNSHealthyWithOneDomainFailure(t *testing.T) {
	c := dnsChecker(t)
	c.lookupHost = func(ctx context.Context, name string) ([]string, error) {
		if name == "example.com" {
			return nil, errors.New("domain unavailable")
		}
		return []string{"192.0.2.2"}, nil
	}
	r := c.CheckFast(context.Background())
	if !r.Healthy || r.DNS == nil || !r.DNS.Healthy {
		t.Fatalf("single domain failure degraded DNS: %+v", r)
	}
}

func TestDNSProbeCancellationAndOptOut(t *testing.T) {
	c := dnsChecker(t)
	c.lookupHost = func(ctx context.Context, name string) ([]string, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := c.CheckFast(ctx)
	if r.Healthy || time.Since(start) > time.Second {
		t.Fatalf("DNS timeout not respected: %+v", r)
	}
	c.cfg.DNSCanaries = nil
	r = c.CheckDetailed(context.Background())
	if !r.Healthy || r.DNS != nil {
		t.Fatalf("DNS opt out ignored: %+v", r)
	}
}
