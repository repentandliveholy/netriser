// Package setup implements `netriser setup`: the installation questions, which
// can be answered again at any time to reconfigure an installed host.
package setup

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/repentandliveholy/netriser/internal/canary"
	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
)

// Detected is a VPN or overlay interface present on this host.
type Detected struct {
	Interface string
	Name      string
	Kind      netengine.OverlayKind
}

// Options configures a setup run. Probe, Detect and Uplink are replaceable
// for tests; nil selects the real implementations.
type Options struct {
	ConfigPath  string
	Interactive bool
	In          io.Reader
	Out         io.Writer
	// Explicit settings (installer flags or environment) are applied without
	// asking the corresponding question.
	Explicit map[string]any
	GOOS     string
	Probe    func(context.Context, *config.Config) canary.HealthResult
	Detect   func() []Detected
	Uplink   func(context.Context, *config.Config) string
}

// Current loads the settings that questions offer as defaults: the existing
// configuration, a legacy Mesh Watchdog configuration (default path only, as
// the installer migrates it there), or new-install values.
func Current(path string) (cfg *config.Config, existing bool, err error) {
	if path == "" {
		path = config.DefaultConfigPath()
	}
	candidates := []string{path}
	if path == config.DefaultConfigPath() {
		candidates = append(candidates, config.LegacyConfigPath())
	}
	for _, p := range candidates {
		if _, statErr := os.Stat(p); statErr == nil {
			cfg, err = config.Load(p)
			return cfg, true, err
		}
	}
	return config.TemplateConfig(), false, nil
}

// Run asks the setup questions (or, non-interactively, only takes Explicit)
// and returns the settings to apply with config.Apply.
func Run(ctx context.Context, opts Options) (map[string]any, error) {
	values := map[string]any{}
	for k, v := range opts.Explicit {
		values[k] = v
	}
	current, existing, err := Current(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if !opts.Interactive {
		return values, nil
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.Probe == nil {
		opts.Probe = probe
	}
	if opts.Detect == nil {
		opts.Detect = func() []Detected { return DetectOverlays(opts.GOOS) }
	}
	if opts.Uplink == nil {
		opts.Uplink = detectUplink
	}
	w := &wizard{p: &prompter{r: bufio.NewReader(opts.In), w: opts.Out}, opts: opts, cur: current, values: values, existing: existing}
	if err := w.run(ctx, existing); err != nil {
		return nil, err
	}
	return values, nil
}

type wizard struct {
	p        *prompter
	opts     Options
	cur      *config.Config
	values   map[string]any
	existing bool
}

func (w *wizard) explicit(key string) bool {
	_, ok := w.opts.Explicit[key]
	return ok
}

func (w *wizard) yesNo(key, question string, def bool) (bool, error) {
	if v, ok := w.opts.Explicit[key].(bool); ok {
		return v, nil
	}
	v, err := w.p.yesNo(question, def)
	if err == nil {
		w.values[key] = v
	}
	return v, err
}

func (w *wizard) section(title string) { w.p.printf("\n== %s ==\n", title) }

func (w *wizard) run(ctx context.Context, existing bool) error {
	p := w.p
	path := w.opts.ConfigPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	p.printf("NetRiser setup. Answers are saved to %s.\n", path)
	if existing {
		p.printf("Defaults are your current settings; press Enter to keep each one.\n")
	}
	p.printf("Answer these questions again at any time with: netriser setup\n")

	w.section("Operating mode")
	p.printf("Observation mode is read-only: NetRiser records incidents and the actions it\nwould take, but changes no routes, services, DNS or binaries (no updates).\n")
	if _, err := w.yesNo("observation_mode", "Start in observation (read-only) mode", w.cur.ObservationMode); err != nil {
		return err
	}

	if err := w.probes(ctx); err != nil {
		return err
	}
	if err := w.overlays(); err != nil {
		return err
	}
	if err := w.recovery(ctx); err != nil {
		return err
	}
	if err := w.updates(); err != nil {
		return err
	}
	return w.confirm()
}

func (w *wizard) probes(ctx context.Context) error {
	p := w.p
	w.section("Connectivity probes")
	targets := w.cur.CanaryTargets
	if v, ok := w.opts.Explicit["canary_targets"].([]string); ok {
		targets = v
	}
	if !w.explicit("canary_targets") {
		for {
			answered := w.showProbe(ctx, targets)
			quorum := w.cur.InternetQuorum(len(targets) + boolInt(w.cur.HTTPFallbackURL != ""))
			keepDefault := answered >= quorum
			if !keepDefault {
				p.printf("Only %d of the required %d probes answered. If this network blocks these\nresolvers, enter targets it can reach (host:port), such as your own DNS servers.\n", answered, quorum)
			}
			keep, err := p.yesNo("Use these internet probes", keepDefault)
			if err != nil {
				return err
			}
			if keep {
				break
			}
			next, err := p.list("Internet probes (host:port)", targets)
			if err != nil {
				return err
			}
			if len(next) == 0 {
				p.printf("At least one internet probe is required.\n")
				continue
			}
			if reflect.DeepEqual(next, targets) {
				p.printf("Keeping the current probes.\n")
				break
			}
			targets = next
		}
		w.values["canary_targets"] = targets
	}

	if !w.explicit("mesh_canaries") {
		p.printf("Optional: endpoints reachable only through your mesh/VPN (for example a\nlighthouse or management host) are monitored separately.\n")
		mesh, err := p.list("Mesh/VPN endpoints to monitor (host:port)", w.cur.MeshCanaries)
		if err != nil {
			return err
		}
		w.values["mesh_canaries"] = mesh
	}
	return nil
}

func (w *wizard) showProbe(ctx context.Context, targets []string) int {
	cfg := *w.cur
	cfg.CanaryTargets = targets
	cfg.MeshCanaries = nil
	cfg.DNSCanaries = nil
	w.p.printf("Testing internet probes...\n")
	res := w.opts.Probe(ctx, &cfg)
	answered := 0
	for _, d := range res.Details {
		if d.Group != canary.GroupInternet {
			continue
		}
		if d.Success {
			answered++
			w.p.printf("  ok    %-28s %v\n", d.Target, d.Latency.Round(time.Millisecond))
		} else {
			reason := "no answer"
			if d.Error != nil {
				reason = d.Error.Error()
			}
			w.p.printf("  FAIL  %-28s %s\n", d.Target, reason)
		}
	}
	return answered
}

func (w *wizard) overlays() error {
	p := w.p
	w.section("VPNs and overlay networks")
	detected := w.opts.Detect()
	var vpnIfaces []string
	if len(detected) == 0 {
		p.printf("No VPN or overlay interfaces are active right now. Built-in detection covers\nWireGuard, OpenVPN, IPsec, Tailscale, ZeroTier, NetBird, Nebula, commercial VPN\nclients and generic tunnels.\n")
	} else {
		p.printf("Detected on this host:\n")
		for _, d := range detected {
			p.printf("  %-20s %s (%s)\n", d.Interface, d.Name, d.Kind)
			if d.Kind == netengine.KindVPN {
				vpnIfaces = append(vpnIfaces, d.Interface)
			}
		}
	}

	if !w.explicit("allowed_default_interfaces") {
		p.printf("If this host deliberately sends all of its own traffic through a VPN or an exit\nnode, NetRiser must leave that interface's default route alone.\n")
		full, err := p.yesNo("Does this host route all of its traffic through a VPN or exit node", len(w.cur.AllowedDefaultInterfaces) > 0)
		if err != nil {
			return err
		}
		allowed := []string{}
		if full {
			def := w.cur.AllowedDefaultInterfaces
			if len(def) == 0 {
				def = vpnIfaces
			}
			if allowed, err = p.list("Interfaces allowed to carry the default route", def); err != nil {
				return err
			}
		}
		w.values["allowed_default_interfaces"] = allowed
	}

	p.printf("A full-tunnel VPN (WireGuard, OpenVPN, IPsec, commercial VPN client) can cut\nthe host off when its server is unreachable, especially with a kill-switch.\nRecovering access means removing the VPN's routes or stopping it: traffic then\nleaves outside the VPN. Answer no on hosts that must never leak traffic.\n")
	if _, err := w.yesNo("allow_vpn_bypass", "May NetRiser bypass a full-tunnel VPN that cut this host off", w.cur.AllowVPNBypass); err != nil {
		return err
	}
	return w.customOverlays()
}

var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9@._:${}\- ]+$`)

func (w *wizard) customOverlays() error {
	if w.explicit("overlays") {
		return nil
	}
	p := w.p
	list := append([]config.OverlayConfig{}, w.cur.Overlays...)
	if len(list) > 0 {
		p.printf("Custom VPN/overlay definitions:\n")
		for _, o := range list {
			p.printf("  %s: interface %q, kind %s, services %s\n", o.Name, o.Interface, kindOr(o.Kind), strings.Join(o.Services, ", "))
		}
		keep, err := p.yesNo("Keep these definitions", true)
		if err != nil {
			return err
		}
		if !keep {
			list = nil
		}
	}
	question := "Do you use a VPN or overlay that NetRiser does not recognise"
	for {
		add, err := p.yesNo(question, false)
		if err != nil {
			return err
		}
		if !add {
			break
		}
		question = "Add another one"
		var o config.OverlayConfig
		if o.Name, err = p.text("Name", "custom-vpn"); err != nil {
			return err
		}
		for {
			if o.Interface, err = p.text("Interface name pattern (regular expression, e.g. ^corp[0-9]+$)", ""); err != nil {
				return err
			}
			if _, cerr := regexp.Compile(o.Interface); o.Interface != "" && cerr == nil {
				break
			}
			p.printf("Please enter a valid regular expression.\n")
		}
		mesh, err := p.yesNo("Is it a mesh overlay that should never carry the default route (no = full-tunnel VPN)", false)
		if err != nil {
			return err
		}
		o.Kind = "vpn"
		if mesh {
			o.Kind = "mesh"
		}
		for {
			if o.Services, err = p.list("Services that run it ({iface} = interface name)", nil); err != nil {
				return err
			}
			ok := true
			for _, s := range o.Services {
				ok = ok && serviceNameRe.MatchString(s)
			}
			if ok {
				break
			}
			p.printf("Service names may contain letters, digits, spaces and @ . _ : - $ { }.\n")
		}
		list = append(list, o)
	}
	if list == nil {
		list = []config.OverlayConfig{}
	}
	w.values["overlays"] = list
	return nil
}

func (w *wizard) recovery(ctx context.Context) error {
	p := w.p
	w.section("Recovery actions")
	p.printf("Actions escalate in stages on consecutive failed checks.\n")
	if _, err := w.yesNo("allow_route_sanitation", "Stage 1: remove rogue default routes published by overlays and restore the uplink route", w.cur.AllowRouteSanitation); err != nil {
		return err
	}
	if _, err := w.yesNo("allow_service_quarantine", "Stage 2: stop an overlay service that publishes a rogue route (restarted after recovery)", w.cur.AllowServiceQuarantine); err != nil {
		return err
	}
	if _, err := w.yesNo("allow_network_restart", "Stage 3: restart network components and re-enable a disabled uplink", w.cur.AllowNetworkRestart); err != nil {
		return err
	}
	if w.opts.GOOS == "linux" {
		if _, err := w.yesNo("allow_dns_recovery", "Restore the last working DNS resolver configuration when name resolution fails", w.cur.AllowDNSRecovery); err != nil {
			return err
		}
	}

	if !w.explicit("management_interface") {
		uplink := w.opts.Uplink(ctx, w.cur)
		if uplink != "" {
			p.printf("Detected physical uplink: %s\n", uplink)
		}
		def := w.cur.ManagementInterface
		if def == "" {
			def = "auto"
		}
		iface, err := p.text("Uplink interface (auto = detect automatically)", def)
		if err != nil {
			return err
		}
		if strings.EqualFold(iface, "auto") {
			iface = ""
		}
		w.values["management_interface"] = iface
	}

	p.printf("Emergency reboot is the last resort when nothing else restores connectivity.\nIt waits for a measured continuous outage and a reboot budget.\n")
	reboot, err := w.yesNo("enable_reboot", "Allow emergency host reboot", w.cur.EnableReboot)
	if err != nil {
		return err
	}
	if reboot && !w.explicit("reboot_min_outage_sec") {
		n, err := p.integer("Minimum continuous outage before reboot, seconds", w.cur.RebootMinOutageSec, 60)
		if err != nil {
			return err
		}
		w.values["reboot_min_outage_sec"] = n
	}
	return nil
}

func (w *wizard) updates() error {
	w.section("Updates")
	w.p.printf("Updates come from %s and are installed only with a valid\nrelease signature, never as a downgrade, and not in observation mode.\n", w.cur.UpdateURL)
	_, err := w.yesNo("auto_update", "Enable automatic updates", w.cur.AutoUpdate)
	return err
}

func (w *wizard) confirm() error {
	before, _ := w.cur.Values()
	keys := make([]string, 0, len(w.values))
	for k := range w.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w.section("Summary")
	changes := 0
	for _, k := range keys {
		old, now := canon(before[k]), canon(w.values[k])
		if reflect.DeepEqual(old, now) {
			continue
		}
		changes++
		w.p.printf("  %-28s %s -> %s\n", k, display(old), display(now))
	}
	switch {
	case !w.existing:
		w.p.printf("  A new configuration is created with the answers above%s.\n", map[bool]string{true: " (changes from the defaults are listed)", false: ""}[changes > 0])
	case changes == 0:
		w.p.printf("  No changes to the current settings.\n")
	}
	ok, err := w.p.yesNo("Save these settings", true)
	if err != nil {
		return err
	}
	if !ok {
		return ErrCancelled
	}
	return nil
}

// canon converts a value to its YAML-decoded form for comparison.
func canon(v any) any {
	data, err := yaml.Marshal(map[string]any{"v": v})
	if err != nil {
		return v
	}
	var m map[string]any
	if yaml.Unmarshal(data, &m) != nil {
		return v
	}
	return m["v"]
}

func display(v any) string {
	if v == nil {
		return "(none)"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(data)
}

func kindOr(k string) string {
	if k == "" {
		return "vpn"
	}
	return k
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func probe(ctx context.Context, cfg *config.Config) canary.HealthResult {
	return canary.NewChecker(cfg).CheckDetailed(ctx)
}

// DetectOverlays lists recognised VPN/overlay interfaces that are up and have
// an IPv4 address. Address-less tunnels (for example the system utun devices
// on macOS) carry no IPv4 default route and are omitted.
func DetectOverlays(goos string) []Detected {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Detected
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || !hasIPv4(i) {
			continue
		}
		var o netengine.Overlay
		var ok bool
		if goos == "windows" {
			o, ok = netengine.ClassifyWindows(i.Name, "")
		} else {
			o, ok = netengine.ClassifyUnix(i.Name)
		}
		if ok {
			out = append(out, Detected{Interface: i.Name, Name: o.Name, Kind: o.Kind})
		}
	}
	return out
}

// detectUplink is read-only: the baseline cache is not written.
func detectUplink(ctx context.Context, cur *config.Config) string {
	cfg := *cur
	cfg.StateDir = ""
	cfg.ManagementInterface = ""
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := netengine.NewEngine(&cfg).DetectBaseline(ctx)
	if err != nil {
		return ""
	}
	if b.Gateway != "" {
		return fmt.Sprintf("%s (gateway %s)", b.Interface, b.Gateway)
	}
	return b.Interface
}

func hasIPv4(i net.Interface) bool {
	addrs, err := i.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return true
		}
	}
	return false
}
