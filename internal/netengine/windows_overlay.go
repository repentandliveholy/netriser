package netengine

import (
	"regexp"
	"strings"
)

// Platform-independent Windows overlay logic. It is kept outside the
// windows-tagged engine so that it is unit-tested on every CI platform.

// windowsOverlayRegex matches virtual adapters that must never be selected as
// the physical baseline (including Hyper-V virtual switches).
var windowsOverlayRegex = regexp.MustCompile(`(?i)(netbird|wt[0-9]|zerotier|zt[a-z0-9]|tailscale|nebula|wireguard|wintun|tap-windows|openvpn|hyper-v|vethernet)`)

// windowsRogueOverlayRegex matches VPN and mesh adapters whose default route is
// treated as rogue. Hyper-V switches are excluded: they legitimately carry the
// physical uplink on hosts that use an external virtual switch.
var windowsRogueOverlayRegex = regexp.MustCompile(`(?i)(netbird|^wt[0-9]|zerotier|^zt[a-z0-9]|tailscale|nebula|wireguard|wintun|tap-windows|openvpn)`)

var windowsWireGuardRegex = regexp.MustCompile(`(?i)wireguard`)
var windowsNetbirdAliasRegex = regexp.MustCompile(`(?i)^wt[0-9]`)

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
	Description string
}

// ParseWindowsRoutes parses "alias|prefix|description" lines.
func ParseWindowsRoutes(output string) []WindowsRoute {
	var routes []WindowsRoute
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(parts) < 2 {
			continue
		}
		r := WindowsRoute{Alias: strings.TrimSpace(parts[0]), Prefix: strings.TrimSpace(parts[1])}
		if len(parts) == 3 {
			r.Description = strings.TrimSpace(parts[2])
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

// WindowsRogueRoutes returns overlay default routes that are not permitted by
// allowed_default_interfaces.
func WindowsRogueRoutes(routes []WindowsRoute, allowed func(string) bool) []WindowsRoute {
	var rogue []WindowsRoute
	for _, r := range routes {
		if allowed != nil && allowed(r.Alias) {
			continue
		}
		if windowsRogueOverlayRegex.MatchString(r.Alias) || windowsRogueOverlayRegex.MatchString(r.Description) {
			rogue = append(rogue, r)
		}
	}
	return rogue
}

// WindowsOverlayService returns the Windows service that owns an overlay
// interface, or "" when it is unknown and only the adapter can be disabled.
func WindowsOverlayService(r WindowsRoute) string {
	text := strings.ToLower(r.Alias + " " + r.Description)
	switch {
	case r.IsWindowsWireGuard():
		return WindowsWireGuardServicePrefix + r.Alias
	case strings.Contains(text, "tailscale"):
		return "Tailscale"
	case strings.Contains(text, "zerotier") || strings.HasPrefix(strings.ToLower(r.Alias), "zt"):
		return "ZeroTierOneService"
	case strings.Contains(text, "netbird") || windowsNetbirdAliasRegex.MatchString(r.Alias):
		return "netbird"
	case strings.Contains(text, "nebula"):
		return "nebula"
	}
	return ""
}

// psQuote quotes a value for a single-quoted PowerShell string literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
