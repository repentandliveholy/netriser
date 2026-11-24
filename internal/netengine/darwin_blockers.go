//go:build darwin

package netengine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Local block recovery on macOS (see blockers.go): the components are pf
// (on or off), its main ruleset and anchors, the application firewall's
// "block all incoming connections", the daemons in /Library/LaunchDaemons
// and network extensions (reported only). ProbeLocal is in
// selfprobe_darwin.go.

const (
	pfctl          = "/sbin/pfctl"
	socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	launchDaemons  = "/Library/LaunchDaemons"
)

func (e *DarwinEngine) rules() rulesStore {
	return rulesStore{dir: filepath.Join(e.cfg.StateDir, "rules")}
}

// ListeningPorts reads the listening TCP sockets from netstat.
func (e *DarwinEngine) ListeningPorts(ctx context.Context) (map[int][]string, error) {
	out, err := e.run(ctx, 15*time.Second, "/usr/sbin/netstat", "-an", "-p", "tcp")
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}
	return ParseDarwinNetstatListening(out), nil
}

type pfRuleset struct {
	name   string // "pf:rules" or "pf:anchor:<path>"
	anchor string // "" for the main ruleset
	text   string
	fp     string
}

// pfRulesets lists the main ruleset and the anchors with rules, except
// Apple's own (com.apple), which macOS rewrites as it runs.
func (e *DarwinEngine) pfRulesets(ctx context.Context) ([]pfRuleset, error) {
	main, err := e.run(ctx, 15*time.Second, pfctl, "-s", "rules")
	if err != nil {
		return nil, fmt.Errorf("pfctl -s rules: %v", err)
	}
	var out []pfRuleset
	if t := cleanPf(main); t != "" {
		out = append(out, pfRuleset{name: "pf:rules", text: t, fp: fingerprint(t)})
	}
	var walk func(parent string, depth int)
	walk = func(parent string, depth int) {
		args := []string{"-s", "Anchors"}
		if parent != "" {
			args = []string{"-a", parent, "-s", "Anchors"}
		}
		list, err := e.run(ctx, 15*time.Second, pfctl, args...)
		if err != nil {
			return
		}
		for _, a := range strings.Fields(cleanPf(list)) {
			if strings.HasPrefix(a, "com.apple") {
				continue
			}
			rules, err := e.run(ctx, 15*time.Second, pfctl, "-a", a, "-s", "rules")
			if t := cleanPf(rules); err == nil && t != "" {
				out = append(out, pfRuleset{name: "pf:anchor:" + a, anchor: a, text: t, fp: fingerprint(t)})
			}
			if depth < 3 {
				walk(a, depth+1)
			}
		}
	}
	walk("", 0)
	return out, nil
}

// cleanPf drops pfctl's notices ("No ALTQ support in kernel") from output.
func cleanPf(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "No ALTQ") || strings.HasPrefix(l, "ALTQ related") || strings.HasPrefix(l, "pfctl:") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

// Components lists pf, its rulesets, the application firewall setting,
// launch daemons and network extensions.
func (e *DarwinEngine) Components(ctx context.Context) ([]Component, error) {
	var out []Component
	var errs []string
	if info, err := e.run(ctx, 15*time.Second, pfctl, "-s", "info"); err == nil {
		if on, ok := ParsePfStatus(info); ok {
			start := StartDisabled
			if on {
				start = StartAuto
			}
			out = append(out, Component{Name: "pf:enabled", Kind: KindRules, Kernel: true, Running: on, Start: start})
			if on {
				sets, err := e.pfRulesets(ctx)
				if err != nil {
					errs = append(errs, err.Error())
				}
				for _, r := range sets {
					out = append(out, Component{Name: r.name, Kind: KindRules, Kernel: true, Running: true, Start: StartAuto, Image: r.fp})
				}
			}
		}
	} else {
		errs = append(errs, "pfctl: "+err.Error())
	}

	global, _ := e.run(ctx, 10*time.Second, socketfilterfw, "--getglobalstate")
	block, err := e.run(ctx, 10*time.Second, socketfilterfw, "--getblockall")
	if fwOn, ok := ParseOnOff(global); ok && err == nil {
		if on, ok := ParseOnOff(block); ok {
			start := StartDisabled
			if on {
				start = StartAuto
			}
			out = append(out, Component{Name: "alf:blockall", Kind: KindRules, Running: on && fwOn, Start: start})
		}
	}

	daemons, err := e.daemons(ctx)
	if err != nil {
		errs = append(errs, err.Error())
	}
	out = append(out, daemons...)

	if list, err := e.run(ctx, 15*time.Second, "/usr/bin/systemextensionsctl", "list"); err == nil {
		for id, version := range ParseNetworkExtensions(list) {
			out = append(out, Component{Name: "extension:" + id, Kind: KindExtension, Running: true, Start: StartAuto, Image: version})
		}
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

// daemons lists the launch daemons installed in /Library/LaunchDaemons.
func (e *DarwinEngine) daemons(ctx context.Context) ([]Component, error) {
	files, err := filepath.Glob(filepath.Join(launchDaemons, "*.plist"))
	if err != nil {
		return nil, err
	}
	listOut, _ := e.run(ctx, 15*time.Second, "/bin/launchctl", "list")
	loaded := ParseLaunchctlList(listOut)
	disOut, _ := e.run(ctx, 15*time.Second, "/bin/launchctl", "print-disabled", "system")
	disabled := ParseLaunchctlDisabled(disOut)
	var out []Component
	for _, f := range files {
		js, err := e.run(ctx, 10*time.Second, "/usr/bin/plutil", "-convert", "json", "-o", "-", f)
		if err != nil {
			continue
		}
		p, err := ParseLaunchdJSON(js)
		if err != nil || p.Label == "" {
			continue
		}
		start := StartAuto
		if p.Disabled || disabled[p.Label] {
			start = StartDisabled
		}
		cmd := strings.Join(append([]string{p.Program}, p.ProgramArguments...), " ")
		c := Component{Name: "launchd:" + p.Label, Kind: KindUnit, Start: start, Running: loaded[p.Label], Image: f,
			Firewall: IsFirewallUnit(p.Label, cmd)}
		if st, err := os.Stat(f); err == nil {
			c.Changed = st.ModTime()
		}
		out = append(out, c)
	}
	return out, nil
}

// Signatures: macOS components carry their trust in the inventory.
func (e *DarwinEngine) Signatures(ctx context.Context, comps []Component) (map[string]Signature, error) {
	return map[string]Signature{}, nil
}

// SaveWorkingState keeps a copy of each pf ruleset of the working host.
func (e *DarwinEngine) SaveWorkingState(ctx context.Context, now time.Time) error {
	info, err := e.run(ctx, 15*time.Second, pfctl, "-s", "info")
	if err != nil {
		return err
	}
	if on, _ := ParsePfStatus(info); !on {
		return nil
	}
	sets, err := e.pfRulesets(ctx)
	if err != nil {
		return err
	}
	store := e.rules()
	for _, r := range sets {
		if err := store.save(r.name, r.fp, r.text+"\n", now); err != nil {
			return err
		}
	}
	return nil
}

// DisableComponent turns pf or "block all incoming" off, empties a new pf
// ruleset or puts back the working copy of a changed one, or unloads and
// disables a launch daemon. Network extensions are only reported.
func (e *DarwinEngine) DisableComponent(ctx context.Context, b Blocker) ActionResult {
	act := ActionResult{Type: ActionDisableComponent, Target: b.Name, Status: ActionExecuted}
	fail := func(desc string, err error, out string) ActionResult {
		act.Status, act.Description = ActionFailed, desc
		if err != nil {
			act.Error = strings.TrimSpace(err.Error() + " " + out)
		}
		return act
	}
	store := e.rules()
	switch {
	case b.ReportOnly || b.Kind == KindExtension:
		act.Status, act.Description = ActionSkipped, "Reported only (remove it in System Settings > General > Login Items & Extensions): "+b.Name
	case b.Name == "pf:enabled":
		if out, err := e.run(ctx, 15*time.Second, pfctl, "-d"); err != nil {
			return fail("Could not turn pf off", err, out)
		}
		act.Description = "Turned pf off (on since the host last worked)"
	case b.Name == "alf:blockall":
		if out, err := e.run(ctx, 15*time.Second, socketfilterfw, "--setblockall", "off"); err != nil {
			return fail("Could not turn off \"block all incoming connections\"", err, out)
		}
		act.Description = "Turned off the application firewall's \"block all incoming connections\""
	case strings.HasPrefix(b.Name, "pf:"):
		anchor := strings.TrimPrefix(b.Name, "pf:anchor:")
		var base []string
		if anchor != b.Name {
			base = []string{"-a", anchor}
		}
		cur, err := e.run(ctx, 15*time.Second, pfctl, append(append([]string{}, base...), "-s", "rules")...)
		if err != nil {
			return fail("Could not read "+b.Name, err, cur)
		}
		if err := store.writeBackup(b.Name, cleanPf(cur)+"\n"); err != nil {
			return fail("Could not save "+b.Name+" before changing it", err, "")
		}
		if b.New {
			if out, err := e.run(ctx, 15*time.Second, pfctl, append(append([]string{}, base...), "-F", "rules")...); err != nil {
				return fail("Could not empty "+b.Name, err, out)
			}
			act.Description = "Emptied " + b.Name + " (new since the host last worked)"
			return act
		}
		work, ok := store.working(b.Name, b.Image, b.RestoreBefore)
		if !ok {
			act.Status, act.Description = ActionSkipped, "No working copy of "+b.Name+" to put back"
			return act
		}
		if out, err := e.loadPf(ctx, base, work); err != nil {
			return fail("Could not put back "+b.Name, err, out)
		}
		act.Description = "Put back the working copy of " + b.Name
	case b.Kind == KindUnit:
		label := strings.TrimPrefix(b.Name, "launchd:")
		_, _ = e.run(ctx, 30*time.Second, "/bin/launchctl", "bootout", "system/"+label)
		if out, err := e.run(ctx, 15*time.Second, "/bin/launchctl", "disable", "system/"+label); err != nil {
			return fail("Could not disable "+label, err, out)
		}
		act.Description = "Stopped and disabled launch daemon " + label
	default:
		act.Status, act.Description = ActionSkipped, "Unknown component "+b.Name
	}
	return act
}

// loadPf loads rules into the main ruleset (filter rules only) or an anchor.
func (e *DarwinEngine) loadPf(ctx context.Context, base []string, text string) (string, error) {
	file, err := e.rules().writeTemp(text)
	if err != nil {
		return "", err
	}
	defer os.Remove(file)
	args := append([]string{}, base...)
	if len(base) == 0 {
		args = append(args, "-R")
	}
	return e.run(ctx, 15*time.Second, pfctl, append(args, "-f", file)...)
}

// RestoreComponent undoes DisableComponent.
func (e *DarwinEngine) RestoreComponent(ctx context.Context, name string, start int) ActionResult {
	act := ActionResult{Type: ActionRestoreComponent, Target: name, Status: ActionExecuted}
	fail := func(desc string, err error, out string) ActionResult {
		act.Status, act.Description = ActionFailed, desc
		act.Error = strings.TrimSpace(err.Error() + " " + out)
		return act
	}
	switch {
	case name == "pf:enabled":
		if out, err := e.run(ctx, 15*time.Second, pfctl, "-e"); err != nil && !strings.Contains(out, "already enabled") {
			return fail("Could not turn pf on", err, out)
		}
		act.Description = "Turned pf on again"
	case name == "alf:blockall":
		if out, err := e.run(ctx, 15*time.Second, socketfilterfw, "--setblockall", "on"); err != nil {
			return fail("Could not turn \"block all incoming connections\" on", err, out)
		}
		act.Description = "Turned the application firewall's \"block all incoming connections\" on again"
	case strings.HasPrefix(name, "pf:"):
		store := e.rules()
		data, err := os.ReadFile(store.backupPath(name))
		if err != nil {
			return fail("No saved copy of "+name, err, "")
		}
		var base []string
		if anchor := strings.TrimPrefix(name, "pf:anchor:"); anchor != name {
			base = []string{"-a", anchor}
		}
		if out, err := e.loadPf(ctx, base, string(data)); err != nil {
			return fail("Could not load the saved copy of "+name, err, out)
		}
		os.Remove(store.backupPath(name))
		act.Description = "Loaded the saved copy of " + name
	case strings.HasPrefix(name, "launchd:"):
		label := strings.TrimPrefix(name, "launchd:")
		if out, err := e.run(ctx, 15*time.Second, "/bin/launchctl", "enable", "system/"+label); err != nil {
			return fail("Could not enable "+label, err, out)
		}
		act.Description = "Enabled launch daemon " + label + " again (starts at the next restart, or now with: sudo launchctl bootstrap system " + filepath.Join(launchDaemons, label+".plist") + ")"
	default:
		act.Status, act.Description = ActionSkipped, "Nothing to restore for "+name
	}
	return act
}
