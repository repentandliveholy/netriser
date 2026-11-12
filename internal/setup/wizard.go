// Package setup implements `netriser setup`: the installation questions, which
// can be answered again at any time to reconfigure an installed host.
package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/repentandliveholy/netriser/internal/canary"
	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/i18n"
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
	Uplink   func(context.Context, *config.Config) (iface, gateway string)
	// Language, when set, is used for the questions instead of asking.
	Language string
}

// EffectiveLanguage is the configured language; an unset language is English.
func EffectiveLanguage(cfg *config.Config) string {
	if l := i18n.Normalize(cfg.Language); l != "" {
		return l
	}
	return "en"
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
	w := &wizard{p: newPrompter(opts.In, opts.Out, existing), opts: opts, cur: current, values: values, existing: existing}
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

func (w *wizard) yesNo(key, question string, def bool, rec *bool) (bool, error) {
	if v, ok := w.opts.Explicit[key].(bool); ok {
		return v, nil
	}
	v, err := w.p.yesNo(question, def, rec)
	if err == nil {
		w.values[key] = v
	}
	return v, err
}

func ptr(b bool) *bool { return &b }

// sectionCount is the number of numbered sections, the summary included.
const sectionCount = 6

func (w *wizard) section(key string) {
	w.p.sec++
	w.p.q = 0
	w.p.printf("\n%s\n", w.p.s.Title("== "+w.p.t("section", w.p.sec, sectionCount, w.p.t(key))+" =="))
	w.p.grouped = true
}

func (w *wizard) run(ctx context.Context, existing bool) error {
	p := w.p
	if lang := i18n.Normalize(fmt.Sprint(w.opts.Explicit["language"])); lang != "" {
		p.lang = lang
	} else if lang := i18n.Normalize(w.opts.Language); lang != "" {
		p.lang = lang
		if lang != EffectiveLanguage(w.cur) {
			w.values["language"] = lang
		}
	} else {
		def := i18n.Normalize(w.cur.Language)
		if def == "" {
			def = i18n.FromEnvironment()
		}
		if def == "" {
			def = "en"
		}
		lang, err := p.chooseLanguage(def)
		if err != nil {
			return err
		}
		p.lang = lang
		w.values["language"] = lang
	}

	path := w.opts.ConfigPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	p.printf("\n%s\n", p.s.Bold(p.t("intro_saved", path)))
	if existing {
		p.note(p.t("intro_existing"))
	} else {
		p.note(p.t("intro_new"))
	}
	p.explain(p.t("intro_howto"))
	p.explain(p.t("intro_rerun"))

	w.section("sec_mode")
	p.explain(p.t("obs_explain"))
	var obsRec *bool
	if !existing {
		obsRec = ptr(true)
	}
	if _, err := w.yesNo("observation_mode", p.t("obs_q"), w.cur.ObservationMode, obsRec); err != nil {
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
	w.section("sec_probes")
	targets := w.cur.CanaryTargets
	if v, ok := w.opts.Explicit["canary_targets"].([]string); ok {
		targets = v
	}
	if !w.explicit("canary_targets") {
		p.explain(p.t("probes_explain"))
		for {
			answered := w.showProbe(ctx, targets)
			quorum := w.cur.InternetQuorum(len(targets) + boolInt(w.cur.HTTPFallbackURL != ""))
			keepDefault := answered >= quorum
			if !keepDefault {
				p.warn(p.t("probes_short", answered, quorum))
			}
			keep, err := p.yesNo(p.t("probes_q"), keepDefault, ptr(keepDefault))
			if err != nil {
				return err
			}
			if keep {
				break
			}
			next, err := p.list(p.t("probes_list_q"), targets, false)
			if err != nil {
				return err
			}
			if len(next) == 0 {
				p.warn(p.t("probes_needed"))
				continue
			}
			if reflect.DeepEqual(next, targets) {
				p.note(p.t("probes_kept"))
				break
			}
			targets = next
		}
		w.values["canary_targets"] = targets
	}

	return nil
}

// accessAddresses asks for the access check addresses; the explanation says
// what happens on access loss in the chosen mode.
func (w *wizard) accessAddresses(accessFirst bool) error {
	if w.explicit("mesh_canaries") {
		return nil
	}
	p := w.p
	effect := p.t("access_effect_log")
	if accessFirst {
		effect = p.t("access_effect_bypass")
	}
	p.explain(p.t("mesh_explain") + " " + effect)
	mesh, err := p.list(p.t("mesh_q"), w.cur.MeshCanaries, false)
	if err != nil {
		return err
	}
	w.values["mesh_canaries"] = mesh
	return nil
}

func (w *wizard) showProbe(ctx context.Context, targets []string) int {
	p := w.p
	cfg := *w.cur
	cfg.CanaryTargets = targets
	cfg.MeshCanaries = nil
	cfg.DNSCanaries = nil
	p.printf("%s\n", p.t("probes_testing"))
	res := w.opts.Probe(ctx, &cfg)
	answered := 0
	for _, d := range res.Details {
		if d.Group != canary.GroupInternet {
			continue
		}
		if d.Success {
			answered++
			p.printf("  %s %-28s %v\n", p.s.Green(fmt.Sprintf("%-6s", p.t("probe_ok"))), d.Target, d.Latency.Round(time.Millisecond))
		} else {
			reason := p.t("probe_noanswer")
			if d.Error != nil {
				reason = d.Error.Error()
			}
			p.printf("  %s %-28s %s\n", p.s.Red(fmt.Sprintf("%-6s", p.t("probe_fail"))), d.Target, reason)
		}
	}
	return answered
}

func (w *wizard) overlays() error {
	p := w.p
	w.section("sec_overlays")
	detected := w.opts.Detect()
	var vpnIfaces []string
	if len(detected) == 0 {
		p.note(p.t("ov_none"))
	} else {
		p.printf("%s\n", p.t("ov_detected"))
		for _, d := range detected {
			kind := p.t("kind_vpn")
			if d.Kind == netengine.KindMesh {
				kind = p.t("kind_mesh")
			}
			p.printf("  %-20s %s (%s)\n", p.s.Bold(d.Interface), d.Name, kind)
			if d.Kind == netengine.KindVPN {
				vpnIfaces = append(vpnIfaces, d.Interface)
			}
		}
	}

	full := len(w.cur.AllowedDefaultInterfaces) > 0
	if w.cur.FullTunnel != nil {
		full = *w.cur.FullTunnel
	}
	if v, ok := w.opts.Explicit["full_tunnel"].(bool); ok {
		full = v
	} else {
		p.explain(p.t("ft_explain"))
		var err error
		if full, err = p.yesNo(p.t("ft_q"), full, nil); err != nil {
			return err
		}
		w.values["full_tunnel"] = full
	}

	if !full {
		p.explain(p.t("ft_no_explain"))
		if !w.explicit("allowed_default_interfaces") {
			w.values["allowed_default_interfaces"] = []string{}
		}
		if err := w.accessAddresses(false); err != nil {
			return err
		}
		return w.customOverlays()
	}

	if !w.explicit("allowed_default_interfaces") {
		def := w.cur.AllowedDefaultInterfaces
		if len(def) == 0 {
			def = vpnIfaces
		}
		p.explain(p.t("ft_allowed_explain"))
		allowed, err := p.list(p.t("ft_allowed_q"), def, false)
		if err != nil {
			return err
		}
		w.values["allowed_default_interfaces"] = allowed
	}

	p.explain(p.t("bypass_explain"))
	accessFirst, err := w.yesNo("allow_vpn_bypass", p.t("bypass_q"), w.cur.AllowVPNBypass, nil)
	if err != nil {
		return err
	}
	if err := w.accessAddresses(accessFirst); err != nil {
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
		p.printf("%s\n", p.t("custom_list"))
		for _, o := range list {
			p.printf("%s\n", p.t("custom_item", o.Name, o.Interface, kindOr(o.Kind), strings.Join(o.Services, ", ")))
		}
		keep, err := p.yesNo(p.t("custom_keep_q"), true, ptr(true))
		if err != nil {
			return err
		}
		if !keep {
			list = nil
		}
	}
	p.explain(p.t("custom_explain"))
	question := p.t("custom_add_q")
	for {
		add, err := p.yesNo(question, false, ptr(false))
		if err != nil {
			return err
		}
		if !add {
			break
		}
		question = p.t("custom_more_q")
		var o config.OverlayConfig
		if o.Name, err = p.text(p.t("custom_name_q"), "custom-vpn", "", false); err != nil {
			return err
		}
		for {
			if o.Interface, err = p.text(p.t("custom_iface_q"), "", "", true); err != nil {
				return err
			}
			if _, cerr := regexp.Compile(o.Interface); cerr == nil {
				break
			}
			p.warn(p.t("custom_iface_bad"))
		}
		mesh, err := p.yesNo(p.t("custom_mesh_q"), false, nil)
		if err != nil {
			return err
		}
		o.Kind = "vpn"
		if mesh {
			o.Kind = "mesh"
		}
		for {
			if o.Services, err = p.list(p.t("custom_services_q"), nil, false); err != nil {
				return err
			}
			ok := true
			for _, s := range o.Services {
				ok = ok && serviceNameRe.MatchString(s)
			}
			if ok {
				break
			}
			p.warn(p.t("custom_services_bad"))
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
	w.section("sec_recovery")
	p.explain(p.t("rec_explain"))
	p.explain(p.t("s1_explain"))
	if _, err := w.yesNo("allow_route_sanitation", p.t("s1_q"), w.cur.AllowRouteSanitation, ptr(true)); err != nil {
		return err
	}
	if w.cur.MaxRestoreAttempts > 0 {
		p.explain(p.t("s2_explain", w.cur.MaxRestoreAttempts))
	} else {
		p.explain(p.t("s2_explain_unlimited"))
	}
	if _, err := w.yesNo("allow_service_quarantine", p.t("s2_q"), w.cur.AllowServiceQuarantine, ptr(true)); err != nil {
		return err
	}
	p.explain(p.t("s3_explain"))
	if _, err := w.yesNo("allow_network_restart", p.t("s3_q"), w.cur.AllowNetworkRestart, ptr(true)); err != nil {
		return err
	}
	if w.opts.GOOS == "linux" {
		p.explain(p.t("dns_explain"))
		if _, err := w.yesNo("allow_dns_recovery", p.t("dns_q"), w.cur.AllowDNSRecovery, ptr(true)); err != nil {
			return err
		}
	}

	if !w.explicit("management_interface") {
		p.explain(p.t("uplink_explain"))
		if iface, gateway := w.opts.Uplink(ctx, w.cur); iface != "" {
			shown := iface
			if gateway != "" {
				shown = p.t("uplink_gateway", iface, gateway)
			}
			p.printf("%s\n", p.t("uplink_detected", p.s.Bold(shown)))
		}
		def := w.cur.ManagementInterface
		if def == "" {
			def = "auto"
		}
		iface, err := p.text(p.t("uplink_q"), def, "auto", false)
		if err != nil {
			return err
		}
		if strings.EqualFold(iface, "auto") {
			iface = ""
		}
		w.values["management_interface"] = iface
	}

	p.explain(p.t("reboot_explain"))
	reboot, err := w.yesNo("enable_reboot", p.t("reboot_q"), w.cur.EnableReboot, ptr(false))
	if err != nil {
		return err
	}
	if reboot && !w.explicit("reboot_min_outage_sec") {
		n, err := p.integer(p.t("reboot_min_q"), w.cur.RebootMinOutageSec, 60, config.DefaultConfig().RebootMinOutageSec)
		if err != nil {
			return err
		}
		w.values["reboot_min_outage_sec"] = n
	}
	return nil
}

func (w *wizard) updates() error {
	w.section("sec_updates")
	if config.IsLegacyUpdateURL(w.cur.UpdateURL) {
		w.values["update_url"] = config.DefaultUpdateURL
	}
	w.p.explain(w.p.t("upd_explain", w.cur.EffectiveUpdateURL()))
	_, err := w.yesNo("auto_update", w.p.t("upd_q"), w.cur.AutoUpdate, ptr(true))
	return err
}

// summaryOrder lists settings in question order for the summary.
var summaryOrder = []string{
	"language", "observation_mode", "canary_targets", "full_tunnel",
	"allowed_default_interfaces", "allow_vpn_bypass", "mesh_canaries", "overlays", "allow_route_sanitation",
	"allow_service_quarantine", "allow_network_restart", "allow_dns_recovery",
	"management_interface", "enable_reboot", "reboot_min_outage_sec", "auto_update", "update_url",
}

func (w *wizard) confirm() error {
	p := w.p
	before, _ := w.cur.Values()
	keys := make([]string, 0, len(w.values))
	for _, k := range summaryOrder {
		if _, ok := w.values[k]; ok {
			keys = append(keys, k)
		}
	}
	var rest []string
	for k := range w.values {
		if !slices.Contains(summaryOrder, k) {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	keys = append(keys, rest...)

	w.section("sec_summary")
	p.explain(p.t("sum_explain"))
	width, valueWidth := 0, 0
	labels := map[string]string{}
	for _, k := range keys {
		labels[k] = p.t("lbl_" + k)
		if strings.HasPrefix(labels[k], "lbl_") {
			labels[k] = k
		}
		width = max(width, utf8.RuneCountInString(labels[k]))
		valueWidth = max(valueWidth, utf8.RuneCountInString(w.show(k, canon(w.values[k]))))
	}
	valueWidth = min(valueWidth, 40)
	changes := 0
	for _, k := range keys {
		old, now := canon(before[k]), canon(w.values[k])
		pad := strings.Repeat(" ", width-utf8.RuneCountInString(labels[k]))
		value := w.show(k, now)
		valuePad := strings.Repeat(" ", max(0, valueWidth-utf8.RuneCountInString(value)))
		var status string
		switch {
		case reflect.DeepEqual(old, now) && w.existing:
			status = p.s.Dim(p.t("sum_unchanged"))
		case reflect.DeepEqual(old, now):
			status = p.s.Dim(p.t("sum_default"))
		case w.existing:
			changes++
			value = p.s.Green(value)
			status = p.s.Yellow(p.t("sum_was", w.show(k, old)))
		default:
			changes++
			value = p.s.Green(value)
			status = p.s.Yellow(p.t("sum_default_was", w.show(k, old)))
		}
		p.printf("%s%s%s  %s%s  %s\n", indent, labels[k], pad, value, valuePad, status)
	}
	switch {
	case !w.existing && changes > 0:
		p.note(p.t("sum_new_diff"))
	case !w.existing:
		p.note(p.t("sum_new"))
	case changes == 0:
		p.note(p.t("sum_nochange"))
	}
	ok, err := p.yesNo(p.t("save_q"), true, ptr(true))
	if err != nil {
		return err
	}
	if !ok {
		p.warn(p.t("cancelled"))
		return ErrCancelled
	}
	return nil
}

// show formats a setting value for the summary.
func (w *wizard) show(key string, v any) string {
	switch key {
	case "language":
		if name, ok := i18n.Names[fmt.Sprint(v)]; ok {
			return name
		}
		return i18n.Names["en"]
	case "management_interface":
		if v == nil || v == "" {
			return w.p.t("val_auto")
		}
	}
	switch x := v.(type) {
	case nil:
		return w.p.t("none")
	case bool:
		return word(x)
	case []any:
		if len(x) == 0 {
			return w.p.t("none")
		}
		var parts []string
		for _, item := range x {
			if m, ok := item.(map[string]any); ok && m["name"] != nil {
				parts = append(parts, fmt.Sprint(m["name"]))
			} else {
				parts = append(parts, fmt.Sprint(item))
			}
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(v)
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
func detectUplink(ctx context.Context, cur *config.Config) (string, string) {
	cfg := *cur
	cfg.StateDir = ""
	cfg.ManagementInterface = ""
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := netengine.NewEngine(&cfg).DetectBaseline(ctx)
	if err != nil {
		return "", ""
	}
	return b.Interface, b.Gateway
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
