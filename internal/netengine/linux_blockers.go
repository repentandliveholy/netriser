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

// Local block recovery on Linux (see blockers.go): the components are the
// nftables tables, iptables-legacy tables, enabled systemd services and
// tainted kernel modules. ProbeLocal is in selfprobe_linux.go.

func (e *LinuxEngine) path(p string) string { return filepath.Join(e.fsRoot, p) }

func (e *LinuxEngine) rules() rulesStore {
	return rulesStore{dir: filepath.Join(e.cfg.StateDir, "rules")}
}

// ListeningPorts reads the listening TCP sockets from /proc/net/tcp{,6}.
func (e *LinuxEngine) ListeningPorts(ctx context.Context) (map[int][]string, error) {
	res := map[int][]string{}
	var firstErr error
	for _, f := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		data, err := os.ReadFile(e.path(f.path))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for port, addrs := range ParseProcNetTCP(string(data), f.v6) {
			res[port] = append(res[port], addrs...)
		}
	}
	if len(res) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return res, nil
}

// iptablesTools returns the save and restore commands for kind
// "iptables", "ip6tables" (legacy backend) or "iptables-nft", "ip6tables-nft"
// (nftables backend), or "" when that backend is not in use.
func (e *LinuxEngine) iptablesTools(ctx context.Context, kind string) (save, restore string) {
	family, backend, _ := strings.Cut(kind, "-")
	if backend == "" {
		backend = "legacy"
	}
	if _, err := e.run(ctx, 15*time.Second, family+"-"+backend+"-save"); err == nil {
		return family + "-" + backend + "-save", family + "-" + backend + "-restore"
	}
	want := "legacy"
	if backend == "nft" {
		want = "nf_tables"
	}
	if v, err := e.run(ctx, 5*time.Second, family, "-V"); err == nil && strings.Contains(v, want) {
		return family + "-save", family + "-restore"
	}
	return "", ""
}

// iptablesKinds are the iptables backends and families, as component name
// prefixes.
var iptablesKinds = []string{"iptables", "ip6tables", "iptables-nft", "ip6tables-nft"}

// iptablesNftTable reports whether an nftables table belongs to iptables-nft
// (it is listed and restored with the iptables tools instead).
func iptablesNftTable(name string, covered map[string]bool) bool {
	return covered[name]
}

type linuxTable struct {
	name  string // component name: "nft:inet filter", "iptables:filter"
	fp    string
	text  string
	table RulesTable
}

// rulesTables lists the tables that filter traffic to or from the host.
// Tables of iptables (either backend) are read with iptables-save, which
// prints rules nft cannot load back.
func (e *LinuxEngine) rulesTables(ctx context.Context, full bool) ([]linuxTable, error) {
	var out []linuxTable
	var errs []string
	covered := map[string]bool{} // nft table names listed through iptables-nft
	for _, kind := range iptablesKinds {
		save, _ := e.iptablesTools(ctx, kind)
		if save == "" {
			continue
		}
		text, err := e.run(ctx, 20*time.Second, save)
		if err != nil {
			errs = append(errs, save+": "+err.Error())
			continue
		}
		for _, t := range SplitIptablesSave(text) {
			if strings.HasSuffix(kind, "-nft") {
				fam := "ip"
				if strings.HasPrefix(kind, "ip6") {
					fam = "ip6"
				}
				covered[fam+" "+t.Name] = true
			}
			fp, ok := IptablesFingerprint(t)
			if !ok {
				continue
			}
			out = append(out, linuxTable{name: kind + ":" + t.Name, fp: fp, text: t.Text, table: t})
		}
	}
	args := []string{"-s", "-t", "list", "ruleset"}
	if full {
		args = []string{"-s", "list", "ruleset"}
	}
	if text, err := e.run(ctx, 20*time.Second, "nft", args...); err == nil {
		for _, t := range SplitNftTables(text) {
			if !NftRelevant(t) || iptablesNftTable(t.Name, covered) {
				continue
			}
			out = append(out, linuxTable{name: "nft:" + t.Name, fp: NftFingerprint(t), text: t.Text, table: t})
		}
	} else if len(out) == 0 {
		errs = append(errs, "nft: "+err.Error())
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

// Components lists rulesets, enabled services and tainted kernel modules.
func (e *LinuxEngine) Components(ctx context.Context) ([]Component, error) {
	var out []Component
	var errs []string
	tables, err := e.rulesTables(ctx, false)
	if err != nil {
		errs = append(errs, err.Error())
	}
	for _, t := range tables {
		out = append(out, Component{Name: t.name, Kind: KindRules, Kernel: true, Running: true, Start: StartAuto, Image: t.fp})
	}

	units, err := e.units(ctx)
	if err != nil {
		errs = append(errs, err.Error())
	}
	out = append(out, units...)

	data, err := os.ReadFile(e.path("/proc/modules"))
	if err != nil {
		errs = append(errs, err.Error())
	}
	for _, m := range ParseProcModules(string(data)) {
		taint, _ := os.ReadFile(e.path("/sys/module/" + m + "/taint"))
		t := strings.TrimSpace(string(taint))
		if t == "" {
			continue
		}
		signer := ""
		if strings.Contains(t, "O") && !strings.Contains(t, "E") {
			signer, _ = e.run(ctx, 5*time.Second, "modinfo", "-F", "signer", m)
		}
		version, _ := os.ReadFile(e.path("/sys/module/" + m + "/srcversion"))
		image := strings.TrimSpace(string(version))
		if image == "" {
			image = "taint " + t
		}
		out = append(out, Component{Name: "kmod:" + m, Kind: KindModule, Kernel: true, Running: true, Start: StartAuto,
			Image: image, Untrusted: ModuleUntrusted(t, signer)})
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

// units lists the enabled systemd services.
func (e *LinuxEngine) units(ctx context.Context) ([]Component, error) {
	enabledOut, err := e.run(ctx, 20*time.Second, "systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("systemctl list-unit-files: %v", err)
	}
	var enabled []string
	for _, n := range FirstColumn(enabledOut) {
		if strings.HasSuffix(n, ".service") && !strings.Contains(n, "@.") {
			enabled = append(enabled, n)
		}
	}
	if len(enabled) == 0 {
		return nil, nil
	}
	activeOut, _ := e.run(ctx, 20*time.Second, "systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--no-pager", "--plain")
	active := map[string]bool{}
	for _, n := range FirstColumn(activeOut) {
		active[n] = true
	}
	args := append([]string{"show", "--no-pager", "-p", "Id", "-p", "FragmentPath", "-p", "ExecStartPre", "-p", "ExecStart", "-p", "ExecStartPost", "-p", "ExecReload", "--"}, enabled...)
	showOut, err := e.run(ctx, 30*time.Second, "systemctl", args...)
	if err != nil {
		return nil, fmt.Errorf("systemctl show: %v", err)
	}
	var out []Component
	for _, u := range ParseSystemctlShow(showOut) {
		c := Component{Name: "unit:" + u.ID, Kind: KindUnit, Start: StartAuto, Running: active[u.ID], Image: u.FragmentPath,
			Firewall: IsFirewallUnit(u.ID, u.Exec)}
		if st, err := os.Stat(e.path(u.FragmentPath)); err == nil && u.FragmentPath != "" {
			c.Changed = st.ModTime()
		}
		out = append(out, c)
	}
	return out, nil
}

// Signatures: Linux components carry their trust in the inventory.
func (e *LinuxEngine) Signatures(ctx context.Context, comps []Component) (map[string]Signature, error) {
	return map[string]Signature{}, nil
}

// SaveWorkingState keeps a copy of each ruleset of the working host.
func (e *LinuxEngine) SaveWorkingState(ctx context.Context, now time.Time) error {
	tables, err := e.rulesTables(ctx, true)
	if err != nil {
		return err
	}
	store := e.rules()
	for _, t := range tables {
		if err := store.save(t.name, t.fp, t.text, now); err != nil {
			return err
		}
	}
	return nil
}

func modprobeConf(m string) string {
	return "/etc/modprobe.d/netriser-disabled-" + safeName(m) + ".conf"
}

// DisableComponent stops and disables a service, removes a new table or
// puts back the working copy of a changed one, or blocks and unloads a
// kernel module. What was replaced is saved for RestoreComponent.
func (e *LinuxEngine) DisableComponent(ctx context.Context, b Blocker) ActionResult {
	act := ActionResult{Type: ActionDisableComponent, Target: b.Name, Status: ActionExecuted}
	fail := func(desc string, err error) ActionResult {
		act.Status, act.Description = ActionFailed, desc
		if err != nil {
			act.Error = err.Error()
		}
		return act
	}
	kind, name, _ := strings.Cut(b.Name, ":")
	switch {
	case b.ReportOnly:
		act.Status, act.Description = ActionSkipped, "Reported only: "+b.Name
	case b.Kind == KindUnit:
		if out, err := e.run(ctx, 60*time.Second, "systemctl", "disable", "--now", name); err != nil {
			return fail("Could not disable "+name, fmt.Errorf("%v %s", err, out))
		}
		act.Description = "Stopped and disabled " + name
	case b.Kind == KindModule:
		conf := fmt.Sprintf("# Disabled by NetRiser local block recovery: %s\n# Undo: nr blockers restore %s\nblacklist %s\ninstall %s /bin/false\n", b.Reason, b.Name, name, name)
		if err := os.WriteFile(e.path(modprobeConf(name)), []byte(conf), 0644); err != nil {
			return fail("Could not block "+name+" from loading", err)
		}
		if out, err := e.run(ctx, 30*time.Second, "modprobe", "-r", name); err != nil {
			act.Status = ActionPartial
			act.Description = fmt.Sprintf("Blocked kernel module %s from loading; it is in use (%s) and stays loaded until the next restart", name, strings.TrimSpace(out))
		} else {
			act.Description = "Unloaded kernel module " + name + " and blocked it from loading"
		}
	case kind == "nft":
		return e.disableNft(ctx, b, name, act)
	case strings.HasPrefix(kind, "ip") && strings.Contains(kind, "tables"):
		return e.disableIptables(ctx, b, kind, name, act)
	default:
		act.Status, act.Description = ActionSkipped, "Unknown component "+b.Name
	}
	return act
}

func (e *LinuxEngine) disableNft(ctx context.Context, b Blocker, table string, act ActionResult) ActionResult {
	store := e.rules()
	cur, err := e.run(ctx, 20*time.Second, "nft", append([]string{"-s", "list", "table"}, strings.Fields(table)...)...)
	if err != nil {
		// Removed meanwhile, for example when its firewall service stopped.
		act.Status, act.Description = ActionNotNeeded, "Table "+table+" is already gone"
		return act
	}
	if err := store.writeBackup(b.Name, cur); err != nil {
		act.Status, act.Error, act.Description = ActionFailed, err.Error(), "Could not save "+table+" before changing it"
		return act
	}
	load := "table " + table + "\ndelete table " + table + "\n"
	act.Description = "Removed nftables table " + table + " (new since the host last worked)"
	if !b.New {
		work, ok := store.working(b.Name, b.Image, b.RestoreBefore)
		if !ok {
			act.Status, act.Description = ActionSkipped, "No working copy of table "+table+" to put back"
			return act
		}
		load += work
		act.Description = "Put back the working copy of nftables table " + table
	}
	file, err := store.writeTemp(load)
	if err == nil {
		defer os.Remove(file)
		var out string
		if out, err = e.run(ctx, 30*time.Second, "nft", "-f", file); err != nil {
			err = fmt.Errorf("%v %s", err, out)
		}
	}
	if err != nil {
		act.Status, act.Error, act.Description = ActionFailed, err.Error(), "Could not change nftables table "+table
	}
	return act
}

func (e *LinuxEngine) disableIptables(ctx context.Context, b Blocker, family, table string, act ActionResult) ActionResult {
	save, restore := e.iptablesTools(ctx, family)
	if save == "" {
		act.Status, act.Description = ActionSkipped, family+" tools not found"
		return act
	}
	store := e.rules()
	text, err := e.run(ctx, 20*time.Second, save, "-t", table)
	var cur RulesTable
	if tables := SplitIptablesSave(text); err == nil && len(tables) > 0 {
		cur = tables[0]
	} else {
		act.Status, act.Description = ActionNotNeeded, family+" table "+table+" is empty or gone"
		return act
	}
	if err := store.writeBackup(b.Name, cur.Text); err != nil {
		act.Status, act.Error, act.Description = ActionFailed, err.Error(), "Could not save "+table+" before changing it"
		return act
	}
	load := EmptyIptablesTable(cur)
	act.Description = fmt.Sprintf("Cleared %s table %s (new since the host last worked)", family, table)
	if !b.New {
		work, ok := store.working(b.Name, b.Image, b.RestoreBefore)
		if !ok {
			act.Status, act.Description = ActionSkipped, fmt.Sprintf("No working copy of %s table %s to put back", family, table)
			return act
		}
		load = work
		act.Description = fmt.Sprintf("Put back the working copy of %s table %s", family, table)
	}
	file, err := store.writeTemp(load)
	if err == nil {
		defer os.Remove(file)
		var out string
		if out, err = e.run(ctx, 30*time.Second, restore, file); err != nil {
			err = fmt.Errorf("%v %s", err, out)
		}
	}
	if err != nil {
		act.Status, act.Error, act.Description = ActionFailed, err.Error(), fmt.Sprintf("Could not change %s table %s", family, table)
	}
	return act
}

// RestoreComponent undoes DisableComponent: enables the service (it starts
// at the next boot, or with systemctl start), loads the saved table, or lets
// the module load again.
func (e *LinuxEngine) RestoreComponent(ctx context.Context, compName string, start int) ActionResult {
	act := ActionResult{Type: ActionRestoreComponent, Target: compName, Status: ActionExecuted}
	kind, name, _ := strings.Cut(compName, ":")
	store := e.rules()
	switch kind {
	case "unit":
		if out, err := e.run(ctx, 60*time.Second, "systemctl", "enable", name); err != nil {
			act.Status, act.Error, act.Description = ActionFailed, fmt.Sprintf("%v %s", err, out), "Could not enable "+name
			return act
		}
		act.Description = "Enabled " + name + " again (starts at the next boot, or now with: systemctl start " + name + ")"
	case "kmod":
		if err := os.Remove(e.path(modprobeConf(name))); err != nil && !os.IsNotExist(err) {
			act.Status, act.Error, act.Description = ActionFailed, err.Error(), "Could not unblock "+name
			return act
		}
		act.Description = "Kernel module " + name + " may load again (at the next boot, or now with: modprobe " + name + ")"
	case "nft", "iptables", "ip6tables", "iptables-nft", "ip6tables-nft":
		data, err := os.ReadFile(store.backupPath(compName))
		if err != nil {
			act.Status, act.Error, act.Description = ActionFailed, err.Error(), "No saved copy of "+compName
			return act
		}
		load, cmd := string(data), "nft"
		args := []string{"-f"}
		if kind == "nft" {
			load = "table " + name + "\ndelete table " + name + "\n" + load
		} else {
			_, cmd = e.iptablesTools(ctx, kind)
			args = nil
		}
		file, err := store.writeTemp(load)
		if err == nil {
			defer os.Remove(file)
			var out string
			if out, err = e.run(ctx, 30*time.Second, cmd, append(args, file)...); err != nil {
				err = fmt.Errorf("%v %s", err, out)
			}
		}
		if err != nil || cmd == "" {
			if err == nil {
				err = fmt.Errorf("%s tools not found", kind)
			}
			act.Status, act.Error, act.Description = ActionFailed, err.Error(), "Could not load the saved copy of "+compName
			return act
		}
		os.Remove(store.backupPath(compName))
		act.Description = "Loaded the saved copy of " + compName
	default:
		act.Status, act.Description = ActionSkipped, "Nothing to restore for "+compName
	}
	return act
}
