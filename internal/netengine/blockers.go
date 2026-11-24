package netengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A local blocker is software on the host itself, typically a firewall
// driver (a Windows Filtering Platform callout), that holds or drops
// connections: the host keeps running and its VPN client may still answer
// pings, but no TCP connection to SSH or RDP gets through. Route repair,
// network restarts and reboots do not help, because the blocker is loaded
// again at the next start. Recovery disables the components that appeared
// since the host was last known to work.

const (
	ActionDisableComponent ActionType = "disable_component"
	ActionRestoreComponent ActionType = "restore_component"
)

// Service start types (the Start value of a Windows service key).
const (
	StartBoot     = 0
	StartSystem   = 1
	StartAuto     = 2
	StartDemand   = 3
	StartDisabled = 4
)

// Component is a Windows service or driver as recorded in the registry.
type Component struct {
	Name string `json:"name"`
	// Kernel is true for kernel and file-system drivers.
	Kernel bool `json:"kernel,omitempty"`
	Start  int  `json:"start"`
	// Shared is true for services that run inside a shared host process.
	Shared    bool     `json:"shared,omitempty"`
	Image     string   `json:"image,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
	// Device is true for drivers bound to hardware (network card, disk,
	// GPU). They are never disabled: the host may not start without them.
	Device bool `json:"device,omitempty"`
	// Running: loaded (driver) or running (service) now.
	Running bool `json:"running,omitempty"`
	// Package: installed from a driver package (.inf), as Windows' own
	// drivers are; drivers created directly with the service manager are not.
	Package bool `json:"package,omitempty"`
	// Changed is when the registry entry was last written.
	Changed time.Time `json:"changed,omitempty"`
}

// Signature describes the code signature of a component's image file.
type Signature struct {
	// Valid: a trusted signature. Windows loads kernel drivers without one
	// only in test mode (TESTSIGNING).
	Valid bool `json:"valid"`
	// Microsoft: signed by Microsoft as part of Windows.
	Microsoft bool   `json:"microsoft"`
	Signer    string `json:"signer,omitempty"`
	Status    string `json:"status,omitempty"`
}

// Blocker is a component chosen for disabling, with the reason.
type Blocker struct {
	Component
	Reason string    `json:"reason"`
	Sig    Signature `json:"signature"`
}

// SnapshotEntry is a component seen while the host worked.
type SnapshotEntry struct {
	Start     int       `json:"start"`
	Image     string    `json:"image,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

// ComponentSnapshot lists the components present while the host worked.
type ComponentSnapshot struct {
	TakenAt    time.Time                `json:"taken_at"`
	Components map[string]SnapshotEntry `json:"components"`
}

// MergeSnapshot updates snap with the components present now. New or changed
// components are first seen now; in the first snapshot they count from their
// last registry change, so long-installed software is known at once while a
// component installed minutes before NetRiser is not. It reports whether
// anything other than the time changed.
func MergeSnapshot(snap *ComponentSnapshot, comps []Component, now time.Time) bool {
	first := snap.Components == nil
	if first {
		snap.Components = map[string]SnapshotEntry{}
	}
	changed := first
	seen := map[string]bool{}
	for _, c := range comps {
		key := strings.ToLower(c.Name)
		seen[key] = true
		old, ok := snap.Components[key]
		if ok && old.Start == c.Start && strings.EqualFold(old.Image, c.Image) {
			continue
		}
		since := now
		if first && !c.Changed.IsZero() && c.Changed.Before(now) {
			since = c.Changed
		}
		// Disabling a component is not a change worth distrusting.
		if ok && c.Start == StartDisabled && strings.EqualFold(old.Image, c.Image) {
			since = old.FirstSeen
		}
		snap.Components[key] = SnapshotEntry{Start: c.Start, Image: c.Image, FirstSeen: since}
		changed = true
	}
	for key := range snap.Components {
		if !seen[key] {
			delete(snap.Components, key)
			changed = true
		}
	}
	snap.TakenAt = now
	return changed
}

// BlockerPolicy controls which components may be disabled.
type BlockerPolicy struct {
	// Snapshot of a working host; nil when none was taken yet.
	Snapshot *ComponentSnapshot
	// KnownGoodBefore: snapshot entries first seen before this time are
	// trusted. Entries seen later may have been installed just before the
	// block started.
	KnownGoodBefore time.Time
	// Protected names (case-insensitive, "*" wildcards allowed).
	Protected []string
}

func (p BlockerPolicy) protected(name string) bool {
	n := strings.ToLower(name)
	for _, pat := range p.Protected {
		if ok, _ := path.Match(strings.ToLower(pat), n); ok {
			return true
		}
	}
	return false
}

// knownGood reports whether the component looked the same in a working
// snapshot taken early enough.
func (p BlockerPolicy) knownGood(c Component) bool {
	if p.Snapshot == nil {
		return false
	}
	e, ok := p.Snapshot.Components[strings.ToLower(c.Name)]
	if !ok || !e.FirstSeen.Before(p.KnownGoodBefore) {
		return false
	}
	if !strings.EqualFold(e.Image, c.Image) {
		return false
	}
	// Moving to an earlier start (demand -> automatic) is a change.
	return c.Start >= e.Start
}

// eligible reports whether a component may be disabled at all.
func (p BlockerPolicy) eligible(c Component) bool {
	if c.Start == StartDisabled || c.Device || c.Shared || p.protected(c.Name) {
		return false
	}
	// Boot drivers may be needed to start Windows. A driver that is not
	// loaded cannot be holding connections.
	if c.Kernel && (c.Start == StartBoot || !c.Running) {
		return false
	}
	return true
}

// BlockerCandidates returns the components whose signatures must be checked
// before SelectBlockers can decide. With a snapshot these are the eligible
// components that are new or changed; without one, every eligible kernel
// driver (only an untrusted signature makes it a blocker then).
func BlockerCandidates(comps []Component, p BlockerPolicy) []Component {
	var out []Component
	for _, c := range comps {
		if !p.eligible(c) {
			continue
		}
		if p.Snapshot != nil {
			if p.knownGood(c) {
				continue
			}
			// User-mode services matter when they start by themselves;
			// demand-start ones are pulled in through dependencies below.
			if !c.Kernel && c.Start != StartAuto {
				continue
			}
		} else if !c.Kernel || c.Package {
			// Without a snapshot only drivers created directly (not from a
			// signed driver package) are considered; Windows' own drivers
			// come from packages even when their files show no signature.
			continue
		}
		out = append(out, c)
	}
	return out
}

// SelectBlockers decides which components to disable. sigs maps component
// names (lower case) to the signatures of their images.
//
//   - Components signed by Microsoft are never chosen.
//   - With a snapshot: new or changed components (see BlockerCandidates).
//   - Without one: loaded kernel drivers created directly with the service
//     manager (not from a driver package) and without a trusted signature,
//     which Windows loads only in test mode.
//   - Then services that depend on a chosen driver (they would start it again).
func SelectBlockers(comps []Component, sigs map[string]Signature, p BlockerPolicy) []Blocker {
	var out []Blocker
	chosen := map[string]bool{}
	for _, c := range BlockerCandidates(comps, p) {
		sig := sigs[strings.ToLower(c.Name)]
		// A missing image cannot be loaded, hence cannot block.
		if sig.Microsoft || sig.Status == "Missing" {
			continue
		}
		var reason string
		switch {
		case p.Snapshot == nil && sig.Valid:
			continue
		case p.Snapshot == nil:
			reason = "driver without a trusted signature (test mode)"
		case !sig.Valid && c.Kernel:
			reason = "new since the host last worked; driver without a trusted signature"
		default:
			reason = "new or changed since the host last worked"
		}
		chosen[strings.ToLower(c.Name)] = true
		out = append(out, Blocker{Component: c, Reason: reason, Sig: sig})
	}
	// Connections are held by a driver. When a new driver is found, services
	// are disabled only when they start it (below), not merely for being new.
	for _, b := range out {
		if b.Kernel {
			drivers := out[:0]
			for _, b := range out {
				if b.Kernel {
					drivers = append(drivers, b)
				} else {
					delete(chosen, strings.ToLower(b.Name))
				}
			}
			out = drivers
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	// Add the services that start a chosen driver, repeating for chains.
	for added := true; added; {
		added = false
		for _, c := range comps {
			key := strings.ToLower(c.Name)
			if chosen[key] || !p.eligible(c) || sigs[key].Microsoft {
				continue
			}
			for _, dep := range c.DependsOn {
				if chosen[strings.ToLower(dep)] {
					chosen[key] = true
					out = append(out, Blocker{Component: c, Reason: "starts " + dep, Sig: sigs[key]})
					added = true
					break
				}
			}
		}
	}
	// User-mode services first: stopping them first lets the driver go.
	sort.SliceStable(out, func(i, j int) bool { return !out[i].Kernel && out[j].Kernel })
	return out
}

// DefaultProtectedComponents are never disabled: remote access, the VPN
// clients the host may be reached through, Windows networking and security,
// and NetRiser itself.
var DefaultProtectedComponents = []string{
	"netriser", "mesh-watchdog",
	"sshd", "ssh-agent", "termservice", "umrdpservice", "sessionenv",
	"tailscale", "wintun", "zerotieroneservice", "zttap300", "netbird",
	"wireguard*", "openvpn*", "ovpn*", "tap0901", "tapwindows*",
	"anydesk*", "teamviewer*", "rustdesk*", "parsec*", "radmin*", "rserver3", "raddrv*",
	"vpnagent", "csc_vpnagent", "acsock*", "forti*", "pangps", "pangpd", "dsncservice",
	"ivanti*", "nordvpn*", "protonvpn*", "expressvpn*", "urbanvpn*", "mullvad*", "cloudflarewarp",
	"bfe", "mpssvc", "windefend", "wdfilter", "wdboot", "wdnisdrv", "wdnissvc",
	"tcpip", "tcpip6", "afd", "netbt", "nsi", "dnscache", "dhcp", "netio",
}

// ImageFile turns a service ImagePath into the file it names. systemRoot is
// the Windows directory (C:\Windows).
func ImageFile(image, name string, kernel bool, systemRoot string) string {
	img := strings.TrimSpace(image)
	if img == "" {
		if !kernel {
			return ""
		}
		return systemRoot + `\System32\drivers\` + name + ".sys"
	}
	if strings.HasPrefix(img, `"`) {
		if end := strings.Index(img[1:], `"`); end >= 0 {
			img = img[1 : end+1]
		}
	} else if m := exeArgs.FindStringIndex(img); m != nil {
		img = img[:m[1]]
	}
	img = strings.TrimPrefix(strings.TrimSpace(img), `\??\`)
	lower := strings.ToLower(img)
	switch {
	case strings.HasPrefix(lower, `\systemroot\`):
		img = systemRoot + img[len(`\systemroot`):]
	case strings.HasPrefix(lower, `%systemroot%`):
		img = systemRoot + img[len(`%systemroot%`):]
	case strings.HasPrefix(lower, `%windir%`):
		img = systemRoot + img[len(`%windir%`):]
	case strings.HasPrefix(lower, `system32\`), strings.HasPrefix(lower, `syswow64\`):
		img = systemRoot + `\` + img
	}
	return img
}

// exeArgs ends an unquoted image path at the executable, before arguments.
var exeArgs = regexp.MustCompile(`(?i)\.(exe|sys|dll)(\s|$)`)

// ImageFileFor applies ImageFile to a component.
func ImageFileFor(c Component, systemRoot string) string {
	return ImageFile(c.Image, c.Name, c.Kernel, systemRoot)
}

// IsMicrosoftSigner reports whether a certificate subject belongs to the
// Windows signing certificates. "Microsoft Windows Hardware Compatibility
// Publisher" signs third-party drivers and does not count.
func IsMicrosoftSigner(subject string) bool {
	if !cnRe.MatchString(subject) || !strings.Contains(subject, "O=Microsoft Corporation") {
		return false
	}
	switch SignerName(subject) {
	case "Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation",
		"Microsoft Windows Production PCA 2011", "Microsoft Windows Early Launch Anti-malware Publisher":
		return true
	}
	return false
}

var cnRe = regexp.MustCompile(`CN=(?:"([^"]*)"|([^,]+))`)

// SignerName returns the CN of a certificate subject.
func SignerName(subject string) string {
	if m := cnRe.FindStringSubmatch(subject); m != nil {
		return strings.TrimSpace(m[1] + m[2])
	}
	return subject
}

// --- local access test -----------------------------------------------------

// PortProbe is one connection attempt from the host to its own port.
type PortProbe struct {
	Port  int    `json:"port"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// LocalAccessResult is the outcome of connecting to the host's own ports.
type LocalAccessResult struct {
	Address string      `json:"address,omitempty"`
	Probes  []PortProbe `json:"probes,omitempty"`
}

// Tested reports whether any listening port was tried.
func (r LocalAccessResult) Tested() bool { return len(r.Probes) > 0 }

// Blocked reports whether a listening port refused its own host.
func (r LocalAccessResult) Blocked() bool {
	for _, p := range r.Probes {
		if !p.OK {
			return true
		}
	}
	return false
}

// Summary is a short description for logs, e.g. "22 timeout, 3389 ok".
func (r LocalAccessResult) Summary() string {
	var parts []string
	for _, p := range r.Probes {
		if p.OK {
			parts = append(parts, fmt.Sprintf("%d ok", p.Port))
		} else {
			parts = append(parts, fmt.Sprintf("%d %s", p.Port, p.Error))
		}
	}
	return strings.Join(parts, ", ")
}

// DialFunc opens a TCP connection; tests replace it.
type DialFunc func(ctx context.Context, address string) error

// DefaultDial connects and closes at once.
func DefaultDial(ctx context.Context, address string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return c.Close()
}

// LocalListener lists the TCP ports the host listens on, with the local
// addresses they are bound to.
type LocalListener interface {
	ListeningPorts(ctx context.Context) (map[int][]string, error)
}

// TestLocalAccess connects from the host to its own address on each access
// port that is listening there. A port that listens but does not accept its
// own host is held or dropped by a local filter: nothing on the network is
// involved. Ports bound only to loopback or another address are skipped.
func TestLocalAccess(ctx context.Context, ip string, ports []int, listening map[int][]string, timeout time.Duration, dial DialFunc) LocalAccessResult {
	res := LocalAccessResult{Address: ip}
	if ip == "" || net.ParseIP(ip) == nil {
		return res
	}
	if dial == nil {
		dial = DefaultDial
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range ports {
		if !listensOn(listening[port], ip) {
			continue
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			err := dial(cctx, net.JoinHostPort(ip, strconv.Itoa(port)))
			p := PortProbe{Port: port, OK: err == nil}
			if err != nil {
				p.Error = dialError(err)
			}
			mu.Lock()
			res.Probes = append(res.Probes, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sort.Slice(res.Probes, func(i, j int) bool { return res.Probes[i].Port < res.Probes[j].Port })
	return res
}

func listensOn(addrs []string, ip string) bool {
	for _, a := range addrs {
		if a == "0.0.0.0" || a == ip || ((a == "::" || a == "[::]") && strings.Contains(ip, ":")) {
			return true
		}
	}
	return false
}

func dialError(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "timeout"
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}

// ParseNetstatListening reads `netstat -ano -p TCP` (and TCPv6) output into
// port -> local addresses in the LISTENING state.
func ParseNetstatListening(out string) map[int][]string {
	res := map[int][]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.EqualFold(f[0], "TCP") || !strings.EqualFold(f[3], "LISTENING") {
			continue
		}
		local := f[1]
		i := strings.LastIndex(local, ":")
		if i <= 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		addr := strings.Trim(local[:i], "[]")
		if i := strings.Index(addr, "%"); i >= 0 {
			addr = addr[:i]
		}
		res[port] = append(res[port], addr)
	}
	return res
}

// BlockerEngine is implemented by engines that can inspect and disable
// local components (Windows).
type BlockerEngine interface {
	LocalListener
	// Components lists services and drivers.
	Components(ctx context.Context) ([]Component, error)
	// Signatures checks the image files of the given components, keyed by
	// lower-case component name.
	Signatures(ctx context.Context, comps []Component) (map[string]Signature, error)
	// DisableComponent sets the component to Disabled and stops it.
	DisableComponent(ctx context.Context, c Component) ActionResult
	// RestoreComponent sets the start type back; it does not start it.
	RestoreComponent(ctx context.Context, name string, start int) ActionResult
}

// StartName names a start type for messages.
func StartName(start int) string {
	switch start {
	case StartBoot:
		return "boot"
	case StartSystem:
		return "system"
	case StartAuto:
		return "automatic"
	case StartDemand:
		return "manual"
	case StartDisabled:
		return "disabled"
	}
	return strconv.Itoa(start)
}
