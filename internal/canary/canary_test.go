package canary

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func TestCheckerWithLocalServer(t *testing.T) {
	testURL := "http://canary.test/health"
	cfg := config.DefaultConfig()
	cfg.DNSCanaries = nil // These tests exercise transport probes only.
	cfg.CanaryTargets = []string{}
	cfg.HTTPFallbackURL = testURL
	cfg.ProbeTimeoutSec = 2

	checker := NewChecker(cfg)
	checker.SetHTTPClient(&http.Client{
		Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("OK")),
			}, nil
		}),
	})

	// Test Fast Check
	res := checker.CheckFast(context.Background())
	if !res.Healthy {
		t.Fatalf("expected healthy, got unhealthy: %v", res)
	}
	if res.SuccessfulTarget != testURL {
		t.Fatalf("expected target %s, got %s", testURL, res.SuccessfulTarget)
	}

	// Test Detailed Check
	det := checker.CheckDetailed(context.Background())
	if !det.Healthy {
		t.Fatalf("expected healthy detailed, got: %v", det)
	}
	if len(det.Details) != 1 || !det.Details[0].Success {
		t.Fatalf("expected success in detailed, got: %v", det.Details)
	}
}

func TestCheckerHTTPStatusHandling(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNSCanaries = nil // These tests exercise transport probes only.
	cfg.CanaryTargets = []string{}
	cfg.HTTPFallbackURL = "http://canary.test/status"
	cfg.ProbeTimeoutSec = 2

	checker := NewChecker(cfg)

	// Case 1: 500 Internal Server Error must FAIL
	checker.SetHTTPClient(&http.Client{
		Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("error")),
			}, nil
		}),
	})
	res := checker.CheckFast(context.Background())
	if res.Healthy {
		t.Fatal("HTTP 500 should be considered unhealthy")
	}

	// Case 2: 302 Redirect must SUCCEED
	checker.SetHTTPClient(&http.Client{
		Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(strings.NewReader("redirect")),
			}, nil
		}),
	})
	res = checker.CheckFast(context.Background())
	if !res.Healthy {
		t.Fatal("HTTP 302 redirect should be considered healthy")
	}
}

func TestCheckerInternetDownMeshUp(t *testing.T) {
	// Internet is down, but an internal mesh canary is reachable.
	// Overall health must still be UNHEALTHY because internet is broken!
	cfg := config.DefaultConfig()
	cfg.DNSCanaries = nil // These tests exercise transport probes only.
	cfg.CanaryTargets = []string{}
	cfg.HTTPFallbackURL = "http://internet.test/probe"
	cfg.MeshCanaries = []string{"http://mesh.internal/health"}
	cfg.ProbeTimeoutSec = 2

	checker := NewChecker(cfg)
	checker.SetHTTPClient(&http.Client{
		Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Host, "internet.test") {
				return nil, fmt.Errorf("connection refused")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("mesh ok")),
			}, nil
		}),
	})

	res := checker.CheckFast(context.Background())
	if res.Healthy {
		t.Fatal("overall health must be UNHEALTHY when internet is down, even if mesh is up")
	}
	if res.InternetHealthy {
		t.Fatal("internet_healthy must be false")
	}
	if !res.MeshHealthy {
		t.Fatal("mesh_healthy must be true")
	}
}

func TestCheckerUnreachable(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNSCanaries = nil // These tests exercise transport probes only.
	cfg.CanaryTargets = []string{"198.51.100.254:53421"}
	cfg.HTTPFallbackURL = "http://198.51.100.254:53421"
	cfg.ProbeTimeoutSec = 1

	checker := NewChecker(cfg)
	start := time.Now()
	res := checker.CheckFast(context.Background())
	elapsed := time.Since(start)

	if res.Healthy {
		t.Fatalf("expected unhealthy for dummy address, got: %+v (successful: %s, details: %+v)", res, res.SuccessfulTarget, res.Details)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("probe took too long: %v", elapsed)
	}
	if !strings.Contains(res.SummaryString(), "UNHEALTHY") {
		t.Fatalf("unexpected summary: %s", res.SummaryString())
	}
}

func TestCheckerContextCancellation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNSCanaries = nil // These tests exercise transport probes only.
	cfg.CanaryTargets = []string{"198.51.100.254:53"}
	cfg.HTTPFallbackURL = ""
	cfg.ProbeTimeoutSec = 10 // long timeout

	checker := NewChecker(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	res := checker.CheckFast(ctx)
	elapsed := time.Since(start)

	if res.Healthy {
		t.Fatal("expected unhealthy on cancellation")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("CheckFast did not respect cancellation, took %v", elapsed)
	}
}
