package canary

import (
	"context"
	"fmt"
	"runtime"
)

// ProbesBlocked tells filtered internet probes apart from a missing internet.
// When the probes are silent but the system resolver still resolves names and
// the router answers ping, the network itself works and the probe addresses
// are probably blocked here (a national firewall, a corporate filter).
// Restarting the network or rebooting would not help in that case.
//
// It needs dns_canaries and a known gateway; without either it reports false,
// so recovery escalates as usual.
func (c *Checker) ProbesBlocked(ctx context.Context, gateway string) (bool, string) {
	if gateway == "" || len(c.cfg.DNSCanaries) == 0 {
		return false, ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dns := c.checkDNS(ctx)
	if dns == nil || !dns.Healthy {
		return false, ""
	}
	if err := c.pingHost(ctx, gateway); err != nil {
		return false, ""
	}
	return true, fmt.Sprintf("system DNS resolves %s and the router %s answers", dns.SuccessfulTarget, gateway)
}

func (c *Checker) systemPing(ctx context.Context, host string) error {
	return ping(ctx, runtime.GOOS, host, c.cfg.ProbeTimeout())
}
