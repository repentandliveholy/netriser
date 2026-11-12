package netengine

import (
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/repentandliveholy/netriser/internal/config"
)

// OverlayKind separates overlays that should never carry the default route
// from full-tunnel VPNs that do so on purpose.
type OverlayKind string

const (
	// KindMesh overlays (Tailscale, ZeroTier, NetBird, Nebula, ...) normally
	// carry only private routes. Their default route is rogue unless allowed.
	KindMesh OverlayKind = "mesh"
	// KindVPN tunnels capture the default route on purpose and often enforce a
	// kill-switch. They are left alone unless allow_vpn_bypass is set.
	KindVPN OverlayKind = "vpn"
)

// Overlay describes one VPN or overlay protocol.
type Overlay struct {
	Name string
	Kind OverlayKind
	// Unix matches Linux/macOS interface names.
	Unix *regexp.Regexp
	// Windows matches a Windows interface alias or adapter description.
	Windows *regexp.Regexp
	// LinuxServices are systemd units; WindowsServices are service names.
	// "{iface}" expands to the interface name.
	LinuxServices   []string
	WindowsServices []string
}

func rx(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	return regexp.MustCompile(pattern)
}

// builtinOverlays is ordered: specific products before the protocols they use
// (Mullvad before WireGuard), and generic tunnels last. PPP is deliberately
// absent because ppp0 is commonly the physical PPPoE uplink.
var builtinOverlays = []Overlay{
	{Name: "NetBird", Kind: KindMesh, Unix: rx(`^wt[0-9]*$`), Windows: rx(`(?i)netbird|^wt[0-9]`),
		LinuxServices: []string{"netbird", "netbird-client"}, WindowsServices: []string{"netbird"}},
	{Name: "Tailscale", Kind: KindMesh, Unix: rx(`^tailscale[0-9]*$`), Windows: rx(`(?i)tailscale`),
		LinuxServices: []string{"tailscaled"}, WindowsServices: []string{"Tailscale"}},
	// macOS ZeroTier uses feth (fake ethernet) pairs.
	{Name: "ZeroTier", Kind: KindMesh, Unix: rx(`^zt[a-z0-9]+$|^feth[0-9]+$`), Windows: rx(`(?i)zerotier|^zt[a-z0-9]`),
		LinuxServices: []string{"zerotier-one"}, WindowsServices: []string{"ZeroTierOneService"}},
	{Name: "Nebula", Kind: KindMesh, Unix: rx(`^nebula[0-9]*$`), Windows: rx(`(?i)nebula`),
		LinuxServices: []string{"nebula"}, WindowsServices: []string{"nebula"}},
	{Name: "Yggdrasil", Kind: KindMesh, Unix: rx(`^ygg[0-9]*$`), Windows: rx(`(?i)yggdrasil`),
		LinuxServices: []string{"yggdrasil"}, WindowsServices: []string{"Yggdrasil"}},
	{Name: "Mullvad", Kind: KindVPN, Unix: rx(`^wg[0-9]*-mullvad$`), Windows: rx(`(?i)mullvad`),
		LinuxServices: []string{"mullvad-daemon"}, WindowsServices: []string{"MullvadVPN"}},
	{Name: "NordVPN", Kind: KindVPN, Unix: rx(`^nordlynx$|^nordtun`), Windows: rx(`(?i)nordlynx|nordvpn`),
		LinuxServices: []string{"nordvpnd"}},
	{Name: "Cloudflare WARP", Kind: KindVPN, Unix: rx(`^CloudflareWARP$`), Windows: rx(`(?i)cloudflare.?warp`),
		LinuxServices: []string{"warp-svc"}, WindowsServices: []string{"CloudflareWARP"}},
	{Name: "ProtonVPN", Kind: KindVPN, Unix: rx(`^proton`), Windows: rx(`(?i)proton`)},
	{Name: "Cisco AnyConnect", Kind: KindVPN, Unix: rx(`^cscotun`), Windows: rx(`(?i)anyconnect|cisco secure client`),
		LinuxServices: []string{"vpnagentd"}},
	{Name: "GlobalProtect", Kind: KindVPN, Unix: rx(`^gpd[0-9]+$`), Windows: rx(`(?i)pangp|palo alto`),
		WindowsServices: []string{"PanGPS"}},
	{Name: "FortiClient", Kind: KindVPN, Unix: rx(`^fctvpn`), Windows: rx(`(?i)fortinet|forticlient`)},
	{Name: "WireGuard", Kind: KindVPN, Unix: rx(`^wg[-_a-zA-Z0-9]*$`), Windows: rx(`(?i)wireguard`),
		LinuxServices: []string{"wg-quick@{iface}"}, WindowsServices: []string{"WireGuardTunnel${iface}"}},
	{Name: "IPsec", Kind: KindVPN, Unix: rx(`^(ipsec[0-9]*|xfrm[0-9a-z]*|vti[0-9]+)$`), Windows: rx(`(?i)wan miniport \((ikev2|l2tp|pptp|sstp)\)`),
		LinuxServices: []string{"strongswan", "strongswan-starter", "ipsec"}},
	{Name: "OpenVPN", Kind: KindVPN, Unix: rx(`^(tun|tap)[0-9]+$|^ovpn`), Windows: rx(`(?i)openvpn|tap-windows|ovpn-dco`)},
	// macOS shares utun between system services and most VPN clients
	// (including Tailscale and NetBird), so utun cannot be attributed by name.
	{Name: "Generic tunnel", Kind: KindVPN, Unix: rx(`^(tun|tap|utun)[0-9]*$`), Windows: rx(`(?i)wintun|\bvpn\b`)},
}

var overlays atomic.Pointer[[]Overlay]

func init() {
	list := append([]Overlay{}, builtinOverlays...)
	overlays.Store(&list)
}

// ConfigureOverlays installs user overlay definitions ahead of the built-in
// ones. The configuration is validated beforehand, so patterns compile.
func ConfigureOverlays(cfg *config.Config) {
	var list []Overlay
	if cfg != nil {
		for _, o := range cfg.Overlays {
			re, err := regexp.Compile(o.Interface)
			if err != nil {
				continue
			}
			kind := KindVPN
			if o.Kind == string(KindMesh) {
				kind = KindMesh
			}
			list = append(list, Overlay{Name: o.Name, Kind: kind, Unix: re, Windows: re,
				LinuxServices: o.Services, WindowsServices: o.Services})
		}
	}
	list = append(list, builtinOverlays...)
	overlays.Store(&list)
}

// BuiltinOverlays lists the protocols recognised without configuration.
func BuiltinOverlays() []Overlay { return append([]Overlay{}, builtinOverlays...) }

// ClassifyUnix returns the overlay owning a Linux/macOS interface.
func ClassifyUnix(name string) (Overlay, bool) {
	if name == "" {
		return Overlay{}, false
	}
	for _, o := range *overlays.Load() {
		if o.Unix != nil && o.Unix.MatchString(name) {
			return o, true
		}
	}
	return Overlay{}, false
}

// ClassifyWindows returns the overlay owning a Windows adapter.
func ClassifyWindows(alias, description string) (Overlay, bool) {
	for _, o := range *overlays.Load() {
		if o.Windows != nil && ((alias != "" && o.Windows.MatchString(alias)) || (description != "" && o.Windows.MatchString(description))) {
			return o, true
		}
	}
	return Overlay{}, false
}

// Actionable reports whether recovery may remove routes of, or stop, this
// overlay: mesh overlays always, full-tunnel VPNs only with allow_vpn_bypass.
// On a host declared without a full tunnel every overlay is actionable.
func (o Overlay) Actionable(cfg *config.Config) bool {
	return o.Kind == KindMesh || (cfg != nil && (cfg.AllowVPNBypass || cfg.UplinkOnly()))
}

// ServiceKind returns the kind of overlay owning a service name that recovery
// stopped: a Linux unit, a Windows service, or a disabled Windows adapter
// ("adapter:<alias>"). Service names are distinctive enough to check both
// platforms' lists. ok is false for unknown services.
func ServiceKind(service string) (OverlayKind, bool) {
	if alias, found := strings.CutPrefix(service, WindowsAdapterTargetPrefix); found {
		if o, ok := ClassifyWindows(alias, ""); ok {
			return o.Kind, true
		}
		return "", false
	}
	unit := strings.TrimSuffix(service, ".service")
	for _, o := range *overlays.Load() {
		for _, tmpl := range o.LinuxServices {
			if serviceMatches(false, tmpl, unit) {
				return o.Kind, true
			}
		}
		for _, tmpl := range o.WindowsServices {
			if serviceMatches(true, tmpl, service) {
				return o.Kind, true
			}
		}
	}
	return "", false
}

// serviceMatches compares a service template ("{iface}" is a wildcard) with a
// name; Windows service names are case-insensitive.
func serviceMatches(windows bool, tmpl, name string) bool {
	eq := func(a, b string) bool { return a == b }
	prefix := strings.HasPrefix
	if windows {
		eq = strings.EqualFold
		prefix = func(s, p string) bool { return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) }
	}
	before, after, wildcard := strings.Cut(tmpl, "{iface}")
	if !wildcard {
		return eq(tmpl, name)
	}
	return len(name) > len(before)+len(after) && prefix(name, before) &&
		eq(name[len(name)-len(after):], after)
}

// Services returns the overlay's service names for an interface on goos.
func (o Overlay) Services(goos, iface string) []string {
	src := o.LinuxServices
	if goos == "windows" {
		src = o.WindowsServices
	}
	out := make([]string, 0, len(src))
	for _, s := range src {
		out = append(out, strings.ReplaceAll(s, "{iface}", iface))
	}
	return out
}

// actionableUnixOverlay reports whether a Linux/macOS interface is an overlay
// whose default or split-default route recovery may remove.
func actionableUnixOverlay(cfg *config.Config, iface string) bool {
	if cfg != nil && cfg.IsAllowedDefaultInterface(iface) {
		return false
	}
	o, ok := ClassifyUnix(iface)
	return ok && o.Actionable(cfg)
}
