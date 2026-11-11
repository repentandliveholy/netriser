package canary

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type DNSResult struct {
	Healthy          bool     `json:"healthy"`
	SuccessfulTarget string   `json:"successful_target,omitempty"`
	Errors           []string `json:"errors,omitempty"`
}

// checkDNS uses the host resolver, independently of the cancelled IP probes.
// Any successful name is sufficient; a single domain outage must not repair DNS.
func (c *Checker) checkDNS(ctx context.Context) *DNSResult {
	if len(c.cfg.DNSCanaries) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.ProbeTimeout())
	defer cancel()
	type answer struct {
		name string
		err  error
	}
	answers := make(chan answer, len(c.cfg.DNSCanaries))
	for _, name := range c.cfg.DNSCanaries {
		go func(name string) {
			ips, err := c.lookupHost(ctx, name)
			if err == nil && len(ips) == 0 {
				err = fmt.Errorf("empty DNS response")
			}
			answers <- answer{name, err}
		}(name)
	}
	result := &DNSResult{}
	for range c.cfg.DNSCanaries {
		select {
		case a := <-answers:
			if a.err == nil {
				result.Healthy = true
				result.SuccessfulTarget = a.name
				return result
			}
			result.Errors = append(result.Errors, a.name+": "+a.err.Error())
		case <-ctx.Done():
			result.Errors = append(result.Errors, ctx.Err().Error())
			return result
		}
	}
	return result
}

func (c *Checker) withDNS(ctx context.Context, result HealthResult) HealthResult {
	if ctx.Err() != nil {
		result.Healthy = false
		return result
	}
	// DNS cannot distinguish resolver faults from a missing internet route.
	if result.InternetHealthy && ctx.Err() == nil {
		result.DNS = c.checkDNS(ctx)
		if result.DNS != nil && !result.DNS.Healthy {
			result.Healthy = false
		}
	}
	return result
}

func (h HealthResult) DNSOnlyFailure() bool {
	return h.InternetHealthy && h.DNS != nil && !h.DNS.Healthy
}

func (h HealthResult) dnsSummary() string {
	if h.DNS == nil {
		return "not_checked"
	}
	if h.DNS.Healthy {
		return "healthy"
	}
	return "failed: " + strings.Join(h.DNS.Errors, "; ")
}

var systemLookupHost = (&net.Resolver{PreferGo: true}).LookupHost
