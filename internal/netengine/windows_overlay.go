package netengine

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/repentandliveholy/netriser/internal/config"
)

// Platform-independent Windows overlay logic. It is kept outside the
// windows-tagged engine so that it is unit-tested on every CI platform.

// windowsHyperVRegex matches Hyper-V virtual switches. They are never chosen as
// the physical baseline but are not overlays either: on hosts with an external
// virtual switch they legitimately carry the physical uplink.
var windowsHyperVRegex = regexp.MustCompile(`(?i)hyper-v|vethernet`)

var windowsWireGuardRegex = regexp.MustCompile(`(?i)wireguard`)

// isWindowsVirtualAdapter reports adapters that must never be selected as the
// physical baseline: any recognised overlay and Hyper-V switches.
func isWindowsVirtualAdapter(alias, description string) bool {
	if _, ok := ClassifyWindows(alias, description); ok {
		return true
	}
	return windowsHyperVRegex.MatchString(alias) || windowsHyperVRegex.MatchString(description)
}

// WindowsWireGuardServicePrefix is the service name prefix used by WireGuard
// for Windows: each active tunnel runs as WireGuardTunnel$<tunnel name>, and
// the tunnel name is also the interface alias.
const WindowsWireGuardServicePrefix = "WireGuardTunnel$"

// WindowsAdapterTargetPrefix marks a quarantined adapter (rather than a
// service) in the quarantine state so that it is re-enabled on restore.
const WindowsAdapterTargetPrefix = "adapter:"

// windowsRoutePrefixes are the default-route prefixes inspected for hijacks:
// a full default route and the split /1 halves used by many VPN clients.
var windowsRoutePrefixes = []string{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"}

// WindowsRoute is one default or split-default IPv4 route.
type WindowsRoute struct {
	Alias       string
	Prefix      string
	Metric      int // route metric + interface metric; -1 when unknown
	Description string
}

// ParseWindowsRoutes parses "alias|prefix|effective metric|description" lines.
func ParseWindowsRoutes(output string) []WindowsRoute {
	var routes []WindowsRoute
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 4)
		if len(parts) < 2 {
			continue
		}
		r := WindowsRoute{Alias: strings.TrimSpace(parts[0]), Prefix: strings.TrimSpace(parts[1]), Metric: -1}
		if len(parts) >= 3 {
			if m, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && m >= 0 {
				r.Metric = m
			}
		}
		if len(parts) == 4 {
			r.Description = strings.TrimSpace(parts[3])
		}
		if r.Alias != "" && r.Prefix != "" {
			routes = append(routes, r)
		}
	}
	return routes
}

// IsWindowsWireGuard reports whether a route belongs to a WireGuard tunnel.
func (r WindowsRoute) IsWindowsWireGuard() bool {
	return windowsWireGuardRegex.MatchString(r.Description) || windowsWireGuardRegex.MatchString(r.Alias)
}

func (r WindowsRoute) overlay() (Overlay, bool) {
	return ClassifyWindows(r.Alias, r.Description)
}

func (r WindowsRoute) isOverlay() bool {
	_, ok := r.overlay()
	return ok
}

// WindowsRogueRoutes returns overlay default routes that capture traffic and
// are not permitted by allowed_default_interfaces. A full 0.0.0.0/0 overlay
// route with a worse effective metric than the physical default route (for
// example ZeroTier's metric 9999 route) carries no traffic and is left alone.
// Split /1 routes always win over /0, and WireGuard is always suspect because
// its kill-switch blocks untunneled traffic regardless of metrics. Full-tunnel
// VPNs are only considered with allow_vpn_bypass.
func WindowsRogueRoutes(routes []WindowsRoute, cfg *config.Config) []WindowsRoute {
	physicalBest := math.MaxInt
	for _, r := range routes {
		if r.Prefix == "0.0.0.0/0" && !r.isOverlay() && r.Metric >= 0 && r.Metric < physicalBest {
			physicalBest = r.Metric
		}
	}
	var rogue []WindowsRoute
	for _, r := range routes {
		o, ok := r.overlay()
		if !ok || !o.Actionable(cfg) || (cfg != nil && cfg.IsAllowedDefaultInterface(r.Alias)) {
			continue
		}
		if r.Prefix == "0.0.0.0/0" && !r.IsWindowsWireGuard() && r.Metric > physicalBest {
			continue
		}
		rogue = append(rogue, r)
	}
	return rogue
}

// WindowsOverlayService returns the Windows service that owns an overlay
// interface, or "" when it is unknown and only the adapter can be disabled.
func WindowsOverlayService(r WindowsRoute) string {
	if o, ok := r.overlay(); ok {
		if services := o.Services("windows", r.Alias); len(services) > 0 {
			return services[0]
		}
	}
	return ""
}

// psQuote quotes a value for a single-quoted PowerShell string literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
