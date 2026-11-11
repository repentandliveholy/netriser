package canary

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

type ProbeProtocol string

const (
	ProtoTCP  ProbeProtocol = "tcp"
	ProtoUDP  ProbeProtocol = "udp_dns"
	ProtoHTTP ProbeProtocol = "http"
)

type TargetGroup string

const (
	GroupInternet TargetGroup = "internet"
	GroupMesh     TargetGroup = "mesh"
)

type TargetResult struct {
	Target    string        `json:"target"`
	Group     TargetGroup   `json:"group"`
	Protocol  ProbeProtocol `json:"protocol"`
	Success   bool          `json:"success"`
	Cancelled bool          `json:"cancelled,omitempty"`
	Latency   time.Duration `json:"latency"`
	Error     error         `json:"error,omitempty"`
}

type HealthResult struct {
	Healthy          bool           `json:"healthy"`
	InternetHealthy  bool           `json:"internet_healthy"`
	MeshHealthy      bool           `json:"mesh_healthy"`
	SuccessfulTarget string         `json:"successful_target,omitempty"`
	Latency          time.Duration  `json:"latency"`
	CheckedAt        time.Time      `json:"checked_at"`
	Details          []TargetResult `json:"details"`
	DNS              *DNSResult     `json:"dns,omitempty"`
}

// Checker handles connectivity tests against external and internal mesh canaries.
type Checker struct {
	cfg        *config.Config
	httpClient *http.Client
	lookupHost func(context.Context, string) ([]string, error)
}

// NewChecker creates a new Checker from config.
func NewChecker(cfg *config.Config) *Checker {
	timeout := cfg.ProbeTimeout()
	return &Checker{
		cfg:        cfg,
		lookupHost: systemLookupHost,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("stopped after 5 redirects")
				}
				return nil
			},
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext: (&net.Dialer{
					Timeout: timeout,
				}).DialContext,
			},
		},
	}
}

// SetHTTPClient sets custom HTTP client (useful for unit tests and mocks).
func (c *Checker) SetHTTPClient(client *http.Client) {
	if client != nil {
		c.httpClient = client
	}
}

// probeSingle dials target using HTTP, TCP, or UDP DNS and rigorously validates responses.
func (c *Checker) probeSingle(ctx context.Context, target string, group TargetGroup) TargetResult {
	start := time.Now()
	res := TargetResult{
		Target: target,
		Group:  group,
	}

	// 1. HTTP Probe
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		res.Protocol = ProtoHTTP
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
		if err != nil {
			res.Error = err
			return res
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				res.Cancelled = true
			}
			res.Error = err
			return res
		}
		_ = resp.Body.Close()

		// Validate HTTP status: 2xx or 3xx acceptable, 5xx server error is failure
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			res.Success = true
			res.Latency = time.Since(start)
			return res
		}

		res.Error = fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
		res.Latency = time.Since(start)
		return res
	}

	// 2. TCP / UDP Port Probe
	addr := target
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "53")
	}

	d := net.Dialer{
		Timeout: c.cfg.ProbeTimeout(),
	}

	// Try TCP connection to port
	res.Protocol = ProtoTCP
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		res.Success = true
		res.Latency = time.Since(start)
		return res
	}

	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		res.Cancelled = true
		res.Error = err
		return res
	}

	// 3. Fallback UDP DNS Probe
	res.Protocol = ProtoUDP
	udpConn, uerr := d.DialContext(ctx, "udp", addr)
	if uerr == nil {
		defer udpConn.Close()

		// Context cancellation monitor to unblock UDP read immediately
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				_ = udpConn.Close()
			case <-done:
			}
		}()

		queryID := []byte{0x12, 0x34}
		dummyQuery := []byte{
			queryID[0], queryID[1], // ID
			0x01, 0x00, // standard query, recursion desired
			0x00, 0x01, // QDCOUNT = 1
			0x00, 0x00, // ANCOUNT = 0
			0x00, 0x00, // NSCOUNT = 0
			0x00, 0x00, // ARCOUNT = 0
			0x00,       // root domain name ""
			0x00, 0x01, // type A
			0x00, 0x01, // class IN
		}
		_ = udpConn.SetDeadline(time.Now().Add(c.cfg.ProbeTimeout()))
		if _, werr := udpConn.Write(dummyQuery); werr == nil {
			buf := make([]byte, 512)
			if n, rerr := udpConn.Read(buf); rerr == nil && n >= 12 {
				// Validate DNS response packet:
				// 1. Transaction ID matches
				// 2. QR bit (bit 7 of byte 2) must be 1 (Response)
				// 3. RCODE (bits 0-3 of byte 3) should not be 2 (Server failure)
				idMatch := buf[0] == queryID[0] && buf[1] == queryID[1]
				isResponse := (buf[2] & 0x80) != 0
				rcode := buf[3] & 0x0F

				if idMatch && isResponse && rcode != 2 {
					res.Success = true
					res.Latency = time.Since(start)
					return res
				}
			}
		}
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		res.Cancelled = true
	}
	res.Error = err
	res.Latency = time.Since(start)
	return res
}

type targetItem struct {
	target string
	group  TargetGroup
}

// CheckFast performs fast parallel checks across internet and mesh groups.
// It stops probing once the internet quorum (min_healthy_targets) is reached.
func (c *Checker) CheckFast(ctx context.Context) HealthResult {
	if ctx == nil {
		ctx = context.Background()
	}

	var targets []targetItem
	for _, t := range c.cfg.CanaryTargets {
		targets = append(targets, targetItem{target: t, group: GroupInternet})
	}
	if c.cfg.HTTPFallbackURL != "" {
		targets = append(targets, targetItem{target: c.cfg.HTTPFallbackURL, group: GroupInternet})
	}
	for _, m := range c.cfg.MeshCanaries {
		targets = append(targets, targetItem{target: m, group: GroupMesh})
	}

	if len(targets) == 0 {
		return HealthResult{
			Healthy:   false,
			CheckedAt: time.Now(),
		}
	}

	fastCtx, cancel := context.WithTimeout(ctx, c.cfg.ProbeTimeout()+time.Second)
	defer cancel()

	quorum := c.cfg.InternetQuorum(c.internetProbeCount())
	resultChan := make(chan TargetResult, len(targets))
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	for _, item := range targets {
		wg.Add(1)
		go func(it targetItem) {
			defer wg.Done()
			res := c.probeSingle(fastCtx, it.target, it.group)
			resultChan <- res
			// Cancel the remaining probes once enough internet targets answered.
			if res.Success && it.group == GroupInternet {
				mu.Lock()
				successes++
				reached := successes >= quorum
				mu.Unlock()
				if reached {
					cancel()
				}
			}
		}(item)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var allDetails []TargetResult
	internetSuccesses := 0
	meshHealthy := false
	var winningResult *TargetResult

	for res := range resultChan {
		allDetails = append(allDetails, res)
		if res.Success {
			if res.Group == GroupInternet {
				internetSuccesses++
				if winningResult == nil {
					winningResult = &res
				}
			} else if res.Group == GroupMesh {
				meshHealthy = true
			}
		}
	}
	internetHealthy := internetSuccesses >= quorum

	// Filter out "context canceled" errors on probes that were cancelled due to winning probe
	if winningResult != nil {
		for i := range allDetails {
			if !allDetails[i].Success && (allDetails[i].Cancelled || errors.Is(allDetails[i].Error, context.Canceled)) {
				allDetails[i].Error = nil
				allDetails[i].Cancelled = true
			}
		}
	}

	overallHealthy := internetHealthy
	// If no internet targets are configured, mesh health determines overall health
	if len(c.cfg.CanaryTargets) == 0 && c.cfg.HTTPFallbackURL == "" {
		overallHealthy = meshHealthy
	}

	latency := time.Duration(0)
	target := ""
	if winningResult != nil {
		latency = winningResult.Latency
		target = winningResult.Target
	}

	return c.withDNS(ctx, HealthResult{
		Healthy:          overallHealthy,
		InternetHealthy:  internetHealthy,
		MeshHealthy:      meshHealthy,
		SuccessfulTarget: target,
		Latency:          latency,
		CheckedAt:        time.Now(),
		Details:          allDetails,
	})
}

func (c *Checker) internetProbeCount() int {
	n := len(c.cfg.CanaryTargets)
	if c.cfg.HTTPFallbackURL != "" {
		n++
	}
	return n
}

// CheckDetailed probes all canaries without early cancellation to gather complete diagnostic latency.
func (c *Checker) CheckDetailed(ctx context.Context) HealthResult {
	if ctx == nil {
		ctx = context.Background()
	}

	var targets []targetItem
	for _, t := range c.cfg.CanaryTargets {
		targets = append(targets, targetItem{target: t, group: GroupInternet})
	}
	if c.cfg.HTTPFallbackURL != "" {
		targets = append(targets, targetItem{target: c.cfg.HTTPFallbackURL, group: GroupInternet})
	}
	for _, m := range c.cfg.MeshCanaries {
		targets = append(targets, targetItem{target: m, group: GroupMesh})
	}

	detCtx, cancel := context.WithTimeout(ctx, c.cfg.ProbeTimeout()+time.Second)
	defer cancel()

	results := make([]TargetResult, len(targets))
	var wg sync.WaitGroup

	for i, item := range targets {
		wg.Add(1)
		go func(idx int, it targetItem) {
			defer wg.Done()
			results[idx] = c.probeSingle(detCtx, it.target, it.group)
		}(i, item)
	}

	wg.Wait()

	internetSuccesses := 0
	meshHealthy := false
	var firstSuccess TargetResult

	for _, r := range results {
		if r.Success {
			if r.Group == GroupInternet {
				internetSuccesses++
				if firstSuccess.Target == "" {
					firstSuccess = r
				}
			} else if r.Group == GroupMesh {
				meshHealthy = true
			}
		}
	}

	internetHealthy := internetSuccesses >= c.cfg.InternetQuorum(c.internetProbeCount())
	overallHealthy := internetHealthy
	if len(c.cfg.CanaryTargets) == 0 && c.cfg.HTTPFallbackURL == "" {
		overallHealthy = meshHealthy
	}

	return c.withDNS(ctx, HealthResult{
		Healthy:          overallHealthy,
		InternetHealthy:  internetHealthy,
		MeshHealthy:      meshHealthy,
		SuccessfulTarget: firstSuccess.Target,
		Latency:          firstSuccess.Latency,
		CheckedAt:        time.Now(),
		Details:          results,
	})
}

// SummaryString formats a one-line summary for status commands.
func (h HealthResult) SummaryString() string {
	if h.Healthy {
		return fmt.Sprintf("HEALTHY (verified via %s in %v, internet=%t, mesh=%t, dns=%s)", h.SuccessfulTarget, h.Latency.Round(time.Millisecond), h.InternetHealthy, h.MeshHealthy, h.dnsSummary())
	}
	return fmt.Sprintf("UNHEALTHY (internet=%t, mesh=%t, dns=%s)", h.InternetHealthy, h.MeshHealthy, h.dnsSummary())
}
