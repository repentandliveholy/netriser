package netengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

type LinuxEngine struct {
	cfg            *config.Config
	runner         CommandRunner
	resolvConfPath string // Empty selects /etc/resolv.conf; injectable for isolated tests.
}

func (e *LinuxEngine) run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return e.runner.Run(ctx, name, args...)
}

// DetectBaseline never guesses a WAN from adapter names or private addresses.
// A known interface remains authoritative even while administratively DOWN.
// Discovery is read-only; only a healthy watchdog cycle confirms the cache.
func (e *LinuxEngine) DetectBaseline(ctx context.Context) (Baseline, error) {
	b := Baseline{Interface: e.cfg.ManagementInterface, Gateway: e.cfg.ManagementGateway, DetectedAt: time.Now()}
	if b.Interface != "" || b.Gateway != "" {
		b.Source = BaselineSourceConfig
	}
	saved, _ := LoadSavedBaseline(e.cfg.StateDir)
	if saved.IsValid() && !IsIgnoredInterface(saved.Interface) &&
		(b.Interface == "" || b.Interface == saved.Interface) {
		// Query addresses, not operstate: a down WAN can still retain its address.
		b.Interface = saved.Interface
		if b.Source == "" {
			b.Source = BaselineSourceCached
		}
		currentIP := e.getDeviceIPv4(ctx, saved.Interface)
		if currentIP != "" {
			b.IP = currentIP
			if b.Gateway == "" && currentIP == saved.IP {
				b.Gateway = saved.Gateway
			}
			b.LastConfirmed = saved.LastConfirmed
		}
	}
	// Only actual default routes can supply a gateway, and only for the selected interface.
	if b.Interface == "" || b.Gateway == "" {
		var best *RouteEntry
		for _, r := range e.defaultRoutes(ctx) {
			if r.Interface == "" || IsIgnoredInterface(r.Interface) || r.Gateway == "" {
				continue
			}
			if (b.Interface != "" && r.Interface != b.Interface) || (b.Gateway != "" && r.Gateway != b.Gateway) {
				continue
			}
			if best == nil || r.Metric < best.Metric {
				copy := r
				best = &copy
			}
		}
		if best != nil {
			b.Interface = best.Interface
			if b.Gateway == "" {
				b.Gateway = best.Gateway
			}
			if b.Source == "" {
				b.Source = BaselineSourceAuto
			}
		}
	}
	if b.Interface != "" && b.IP == "" {
		b.IP = e.getDeviceIPv4(ctx, b.Interface)
	}
	if err := validateLinuxBaseline(b); err != nil {
		return b, err
	}
	return b, nil
}

func (e *LinuxEngine) defaultRoutes(ctx context.Context) []RouteEntry {
	out, err := e.run(ctx, 3*time.Second, "ip", "-j", "-4", "route", "show", "default")
	if err == nil {
		if routes, parseErr := ParseLinuxRoutesJSON([]byte(out)); parseErr == nil {
			return routes
		}
	}
	out, err = e.run(ctx, 3*time.Second, "ip", "-4", "route", "show", "default")
	if err != nil {
		return nil
	}
	return ParseLinuxRoutesText(out)
}

func validateLinuxBaseline(b Baseline) error {
	ip, gw := net.ParseIP(b.IP), net.ParseIP(b.Gateway)
	if b.Interface == "" || IsIgnoredInterface(b.Interface) || ip == nil || ip.To4() == nil || gw == nil || gw.To4() == nil {
		return fmt.Errorf("refusing network changes without a known physical interface, IPv4 and gateway: %s", b)
	}
	return nil
}

func (e *LinuxEngine) getDeviceIPv4(ctx context.Context, dev string) string {
	// Try JSON structured output first
	out, err := e.run(ctx, 2*time.Second, "ip", "-j", "-4", "addr", "show", "dev", dev)
	if err == nil && len(out) > 0 {
		if ip := ParseLinuxAddrJSON([]byte(out)); ip != "" {
			return ip
		}
	}

	// Fallback to -o addr show
	textOut, err := e.run(ctx, 2*time.Second, "ip", "-4", "-o", "addr", "show", "dev", dev, "scope", "global")
	if err == nil {
		return ParseLinuxAddrText(textOut)
	}
	return ""
}

func (e *LinuxEngine) ApplyPolicyRouting(ctx context.Context, b Baseline) error {
	if err := validateLinuxBaseline(b); err != nil {
		return err
	}
	tableStr := strconv.Itoa(e.cfg.PolicyRoutingTable)
	prioStr := strconv.Itoa(e.cfg.PolicyRoutingPriority)
	// Read rules before changing anything. Never delete another source rule at this priority.
	ruleOut, err := e.run(ctx, 2*time.Second, "ip", "rule", "show")
	if err != nil {
		return fmt.Errorf("read policy rules: %w", err)
	}
	rules := ParseLinuxRules(ruleOut)
	expectedSelector := fmt.Sprintf("from %s lookup %s", b.IP, tableStr)
	ruleExists := false
	for _, r := range rules {
		if r.Priority != e.cfg.PolicyRoutingPriority {
			continue
		}
		selector := strings.ReplaceAll(r.Selector, b.IP+"/32", b.IP)
		if selector == expectedSelector {
			ruleExists = true
			continue
		}
		// Existing source rules using our table are preserved for incoming sessions.
		fields := strings.Fields(selector)
		if len(fields) != 4 || fields[0] != "from" || fields[2] != "lookup" || fields[3] != tableStr {
			return fmt.Errorf("policy priority %s occupied by foreign rule %q", prioStr, r.Selector)
		}
	}
	if _, err := e.run(ctx, 2*time.Second, "ip", "route", "replace", "default", "via", b.Gateway, "dev", b.Interface, "table", tableStr, "onlink"); err != nil {
		return fmt.Errorf("restore policy default route: %w", err)
	}
	if !ruleExists {
		if _, err := e.run(ctx, 2*time.Second, "ip", "rule", "add", "from", b.IP, "lookup", tableStr, "priority", prioStr); err != nil {
			return fmt.Errorf("add management source rule: %w", err)
		}
	}

	return nil
}

func (e *LinuxEngine) RemovePolicyRouting(ctx context.Context, b Baseline) error {
	if err := validateLinuxBaseline(b); err != nil {
		return err
	}
	table, priority := strconv.Itoa(e.cfg.PolicyRoutingTable), strconv.Itoa(e.cfg.PolicyRoutingPriority)
	out, err := e.run(ctx, 2*time.Second, "ip", "rule", "show")
	if err != nil {
		return err
	}
	for _, rule := range ParseLinuxRules(out) {
		selector := strings.ReplaceAll(rule.Selector, b.IP+"/32", b.IP)
		if rule.Priority == e.cfg.PolicyRoutingPriority && selector == fmt.Sprintf("from %s lookup %s", b.IP, table) {
			if _, err := e.run(ctx, 2*time.Second, "ip", "rule", "del", "from", b.IP, "lookup", table, "priority", priority); err != nil {
				return err
			}
		}
	}
	// Do not flush foreign routes or Tailscale rules sharing a table/priority.
	return nil
}

func (e *LinuxEngine) SurgicalCleanRoutes(ctx context.Context, b Baseline) ([]ActionResult, error) {
	if err := validateLinuxBaseline(b); err != nil {
		return nil, err
	}
	var actions []ActionResult

	// 1. Remove rogue default routes on mesh interfaces or foreign gateways in table main
	out, err := e.run(ctx, 3*time.Second, "ip", "-j", "-4", "route", "show", "default")
	var routes []RouteEntry
	if err == nil && len(out) > 0 {
		routes, _ = ParseLinuxRoutesJSON([]byte(out))
	}
	if len(routes) == 0 {
		textOut, tErr := e.run(ctx, 3*time.Second, "ip", "-4", "route", "show", "default")
		if tErr == nil {
			routes = ParseLinuxRoutesText(textOut)
		}
	}

	for _, r := range routes {
		// If interface is explicitly authorized as an exit-node, DO NOT clean its default route!
		if e.cfg.IsAllowedDefaultInterface(r.Interface) {
			continue
		}

		if r.Interface != "" && IsMeshInterface(r.Interface) {
			res := ActionResult{
				Type:        ActionCleanRoute,
				Target:      fmt.Sprintf("default dev %s", r.Interface),
				Status:      ActionExecuted,
				StateBefore: fmt.Sprintf("default via %s dev %s", r.Gateway, r.Interface),
				Description: fmt.Sprintf("Removed unauthorized rogue default route on mesh device %s", r.Interface),
			}
			if _, rErr := e.run(ctx, 2*time.Second, "ip", "route", "del", "default", "dev", r.Interface); rErr != nil {
				res.Status = ActionFailed
				res.Error = rErr.Error()
			}
			actions = append(actions, res)

		}
	}

	// 2. Remove rogue /1 routes (0.0.0.0/1 and 128.0.0.0/1) on mesh interfaces
	for _, halfRoute := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		halfOut, err := e.run(ctx, 2*time.Second, "ip", "-4", "route", "show", halfRoute)
		if err == nil && strings.TrimSpace(halfOut) != "" {
			halfRoutes := ParseLinuxRoutesText(halfOut)
			for _, hr := range halfRoutes {
				if hr.Interface != "" && IsMeshInterface(hr.Interface) && !e.cfg.IsAllowedDefaultInterface(hr.Interface) {
					res := ActionResult{
						Type:        ActionCleanRoute,
						Target:      fmt.Sprintf("%s dev %s", halfRoute, hr.Interface),
						Status:      ActionExecuted,
						StateBefore: fmt.Sprintf("%s dev %s", halfRoute, hr.Interface),
						Description: fmt.Sprintf("Removed rogue /1 route %s on %s", halfRoute, hr.Interface),
					}
					if _, rErr := e.run(ctx, 2*time.Second, "ip", "route", "del", halfRoute, "dev", hr.Interface); rErr != nil {
						res.Status = ActionFailed
						res.Error = rErr.Error()
					}
					actions = append(actions, res)
				}
			}
		}
	}

	// 3. Clean only unauthorized overlay defaults in NetBird tables.
	for _, table := range []string{"netbird", "7120"} {
		out, err := e.run(ctx, 2*time.Second, "ip", "-4", "route", "show", "default", "table", table)
		if err != nil {
			continue
		}
		for _, r := range ParseLinuxRoutesText(out) {
			if !IsMeshInterface(r.Interface) || e.cfg.IsAllowedDefaultInterface(r.Interface) {
				continue
			}
			act := ActionResult{Type: ActionCleanRoute, Target: fmt.Sprintf("default dev %s table %s", r.Interface, table), Status: ActionExecuted, Description: "Removed unauthorized overlay default from policy table"}
			if _, err := e.run(ctx, 2*time.Second, "ip", "route", "del", "default", "dev", r.Interface, "table", table); err != nil {
				act.Status, act.Error = ActionFailed, err.Error()
			}
			actions = append(actions, act)
		}
	}

	// 4. Restore the physical link before restoring main and policy routes.
	linkAction := ActionResult{Type: ActionRestartStack, Target: b.Interface, Status: ActionExecuted, Description: "Ensured physical link is UP"}
	if _, err := e.run(ctx, 2*time.Second, "ip", "link", "set", "dev", b.Interface, "up"); err != nil {
		linkAction.Status, linkAction.Error = ActionFailed, err.Error()
		return append(actions, linkAction), fmt.Errorf("bring WAN up: %w", err)
	}
	actions = append(actions, linkAction)
	routeAction := ActionResult{Type: ActionRestoreRoute, Target: fmt.Sprintf("default via %s dev %s", b.Gateway, b.Interface), Status: ActionExecuted, Description: "Restored main default route with onlink gateway"}
	if _, err := e.run(ctx, 2*time.Second, "ip", "route", "replace", "default", "via", b.Gateway, "dev", b.Interface, "onlink"); err != nil {
		routeAction.Status, routeAction.Error = ActionFailed, err.Error()
	}
	actions = append(actions, routeAction)

	// 5. Re-assert policy routing table
	if pErr := e.ApplyPolicyRouting(ctx, b); pErr != nil {
		actions = append(actions, ActionResult{
			Type:        ActionApplyPolicy,
			Target:      fmt.Sprintf("table %d", e.cfg.PolicyRoutingTable),
			Status:      ActionFailed,
			Error:       pErr.Error(),
			Description: fmt.Sprintf("Failed to re-enforce policy routing table %d", e.cfg.PolicyRoutingTable),
		})
	} else {
		actions = append(actions, ActionResult{
			Type:        ActionApplyPolicy,
			Target:      fmt.Sprintf("table %d", e.cfg.PolicyRoutingTable),
			Status:      ActionExecuted,
			Description: fmt.Sprintf("Re-enforced policy routing table %d", e.cfg.PolicyRoutingTable),
		})
	}

	return actions, nil
}

// Quarantine requires current evidence of an unauthorized default or /1 route.
// A failed internet probe alone is never evidence against every overlay.
func (e *LinuxEngine) QuarantineMeshServices(ctx context.Context) ([]ActionResult, error) {
	b, err := e.DetectBaseline(ctx)
	if err != nil {
		return nil, err
	}
	link, err := e.run(ctx, 2*time.Second, "ip", "-o", "link", "show", "dev", b.Interface)
	if err != nil || !strings.Contains(link, "<") {
		return nil, fmt.Errorf("cannot verify WAN link before quarantine")
	}
	flags := strings.SplitN(strings.SplitN(link, "<", 2)[1], ">", 2)[0]
	if !strings.Contains(","+flags+",", ",UP,") {
		return nil, fmt.Errorf("WAN interface %s is down; preserving overlays", b.Interface)
	}
	suspects := map[string]bool{}
	routes := e.defaultRoutes(ctx)
	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		out, err := e.run(ctx, 2*time.Second, "ip", "-4", "route", "show", dst)
		if err == nil {
			routes = append(routes, ParseLinuxRoutesText(out)...)
		}
	}
	for _, table := range []string{"netbird", "7120"} {
		out, err := e.run(ctx, 2*time.Second, "ip", "-4", "route", "show", "default", "table", table)
		if err == nil {
			routes = append(routes, ParseLinuxRoutesText(out)...)
		}
	}
	for _, r := range routes {
		if e.cfg.IsAllowedDefaultInterface(r.Interface) {
			continue
		}
		switch {
		case strings.HasPrefix(r.Interface, "wt"):
			suspects["netbird"], suspects["netbird-client"] = true, true
		case strings.HasPrefix(r.Interface, "tailscale"):
			suspects["tailscaled"] = true
		case strings.HasPrefix(r.Interface, "nebula"):
			suspects["nebula"] = true
		case strings.HasPrefix(r.Interface, "zt"):
			suspects["zerotier-one"] = true
		}
	}
	var actions []ActionResult
	for _, name := range e.cfg.MonitoredServices {
		if !suspects[name] {
			continue
		}
		if _, err := e.run(ctx, 2*time.Second, "systemctl", "is-active", "--quiet", name); err != nil {
			continue
		}
		act := ActionResult{Type: ActionQuarantineService, Target: name, Status: ActionExecuted, Description: "Stopped service publishing unauthorized routes"}
		if _, err := e.run(ctx, 5*time.Second, "systemctl", "stop", name); err != nil {
			act.Status = ActionFailed
			act.Error = err.Error()
		}
		actions = append(actions, act)
	}
	if len(actions) == 0 {
		actions = append(actions, ActionResult{Type: ActionQuarantineService, Target: "all", Status: ActionSkipped, Description: "No overlay route evidence; preserving management access"})
	}
	return actions, nil
}

func (e *LinuxEngine) RestoreMeshServices(ctx context.Context, services []string) ([]ActionResult, error) {
	var actions []ActionResult
	var failures []error

	// 1. Restart systemd-resolved if present to ensure clean DNS state
	if _, err := e.run(ctx, 2*time.Second, "systemctl", "is-active", "--quiet", "systemd-resolved"); err == nil {
		res := ActionResult{
			Type:        ActionRestartStack,
			Target:      "systemd-resolved",
			Status:      ActionExecuted,
			Description: "Restarted systemd-resolved",
		}
		if _, rErr := e.run(ctx, 5*time.Second, "systemctl", "restart", "systemd-resolved"); rErr != nil {
			res.Status = ActionFailed
			res.Error = rErr.Error()
			failures = append(failures, rErr)
		}
		actions = append(actions, res)
	}

	// 2. Restart quarantined services
	for _, s := range services {
		if s == "" {
			continue
		}
		res := ActionResult{
			Type:        ActionRestoreService,
			Target:      s,
			Status:      ActionExecuted,
			Description: fmt.Sprintf("Restarted mesh service: %s", s),
		}
		if _, rErr := e.run(ctx, 8*time.Second, "systemctl", "restart", s); rErr != nil {
			res.Status = ActionFailed
			res.Error = rErr.Error()
			failures = append(failures, rErr)
		}
		actions = append(actions, res)
	}

	return actions, errors.Join(failures...)
}

func (e *LinuxEngine) RestartNetworkStack(ctx context.Context, b Baseline) error {
	if b.Interface == "" || IsIgnoredInterface(b.Interface) {
		return fmt.Errorf("unknown physical interface; refusing network restart")
	}
	if _, err := e.run(ctx, 3*time.Second, "ip", "link", "set", "dev", b.Interface, "up"); err != nil {
		return fmt.Errorf("bring %s up: %w", b.Interface, err)
	}
	// Reconfigure only the known interface, using the active network manager.
	if _, err := e.run(ctx, 2*time.Second, "systemctl", "is-active", "--quiet", "systemd-networkd"); err == nil {
		if _, err := e.run(ctx, 10*time.Second, "networkctl", "reconfigure", b.Interface); err != nil {
			if _, restartErr := e.run(ctx, 10*time.Second, "systemctl", "restart", "systemd-networkd"); restartErr != nil {
				return fmt.Errorf("networkd reconfigure: %v; restart: %w", err, restartErr)
			}
		}
	} else if _, err := e.run(ctx, 2*time.Second, "systemctl", "is-active", "--quiet", "NetworkManager"); err == nil {
		if _, err := e.run(ctx, 10*time.Second, "nmcli", "device", "reapply", b.Interface); err != nil {
			return fmt.Errorf("NetworkManager reapply: %w", err)
		}
	}
	// DHCP is asynchronous: reconfigure can return before an address and gateway
	// exist. Wait for a complete live baseline instead of reporting a false
	// failure or installing routes for an address which is no longer assigned.
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		refreshed, err := e.DetectBaseline(waitCtx)
		if err == nil && refreshed.Interface == b.Interface {
			b = refreshed
			break
		}
		// A complete caller baseline is still useful for an unmanaged static WAN,
		// but only while that exact address remains assigned to the interface.
		if b.IsValid() && e.getDeviceIPv4(waitCtx, b.Interface) == b.IP {
			break
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("waiting for %s IPv4 address and gateway: %w", b.Interface, waitCtx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	// The OS manager does not restore our separate policy table.
	if err := validateLinuxBaseline(b); err != nil {
		return err
	}
	if _, err := e.run(ctx, 3*time.Second, "ip", "route", "replace", "default", "via", b.Gateway, "dev", b.Interface, "onlink"); err != nil {
		return fmt.Errorf("restore main default route: %w", err)
	}
	return e.ApplyPolicyRouting(ctx, b)
}

func (e *LinuxEngine) EmergencyReboot(ctx context.Context, reason string) error {
	if !e.cfg.EnableReboot {
		return fmt.Errorf("emergency reboot skipped: reboot is disabled in config")
	}

	// Record panic reboot history
	panicLog := filepath.Join(e.cfg.StateDir, "panic_reboot_history.log")
	msg := fmt.Sprintf("[%s] EMERGENCY REBOOT TRIGGERED: %s\n", time.Now().Format("2006-01-02 15:04:05"), reason)
	_ = os.WriteFile(panicLog, []byte(msg), 0640)

	// Sync disks
	_, _ = e.run(ctx, 5*time.Second, "sync")

	// Grace sleep
	grace := e.cfg.RebootGraceSec
	if grace <= 0 {
		grace = 15
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(grace) * time.Second):
	}

	// Clean reboot attempt
	_, _ = e.run(ctx, 10*time.Second, "systemctl", "reboot")
	_, _ = e.run(ctx, 5*time.Second, "reboot")

	// Hard SysRq fallback only if explicitly enabled in configuration
	if e.cfg.EnableSysRqFallback {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Second):
		}
		_, _ = e.run(ctx, 2*time.Second, "sync")
		_ = os.WriteFile("/proc/sys/kernel/sysrq", []byte("1\n"), 0644)
		_ = os.WriteFile("/proc/sysrq-trigger", []byte("b\n"), 0644)
	}

	return nil
}

func (e *LinuxEngine) SimulateHijackSession(ctx context.Context, b Baseline, rollbackDuration time.Duration) (SimulationSession, error) {
	return StartDetachedSimulation(ctx, e.cfg, e.runner, b, rollbackDuration)
}

func (e *LinuxEngine) SimulateHijack(ctx context.Context, b Baseline, rollbackDuration time.Duration) (func(), error) {
	session, err := e.SimulateHijackSession(ctx, b, rollbackDuration)
	if err != nil {
		return nil, err
	}
	return func() {
		_ = session.Disarm()
	}, nil
}

func (e *LinuxEngine) DumpDiagnostics(ctx context.Context, b Baseline) (string, error) {
	var buf bytes.Buffer
	buf.WriteString("=== NETRISER DIAGNOSTIC REPORT (LINUX) ===\n")
	buf.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("Physical Baseline: %s\n\n", b.String()))

	e.appendCmdOutput(ctx, &buf, "--- Default Routes (Table main) ---", "ip", "-4", "route", "show", "default")
	e.appendCmdOutput(ctx, &buf, "--- All Routes (Table main) ---", "ip", "-4", "route", "show")
	e.appendCmdOutput(ctx, &buf, "--- NetBird Table netbird ---", "ip", "-4", "route", "show", "table", "netbird")
	e.appendCmdOutput(ctx, &buf, "--- NetBird Table 7120 ---", "ip", "-4", "route", "show", "table", "7120")
	e.appendCmdOutput(ctx, &buf, "--- Tailscale Table 52 ---", "ip", "-4", "route", "show", "table", "52")
	e.appendCmdOutput(ctx, &buf, fmt.Sprintf("--- Policy Routing Table %d ---", e.cfg.PolicyRoutingTable), "ip", "-4", "route", "show", "table", strconv.Itoa(e.cfg.PolicyRoutingTable))
	e.appendCmdOutput(ctx, &buf, "--- Policy Rules (ip rule) ---", "ip", "rule", "show")
	e.appendCmdOutput(ctx, &buf, "--- Network Interfaces (ip -br link) ---", "ip", "-br", "link")
	e.appendCmdOutput(ctx, &buf, "--- Network Addresses (ip -br addr) ---", "ip", "-br", "addr")

	buf.WriteString("--- Monitored Services Status ---\n")
	for _, s := range e.cfg.MonitoredServices {
		status, _ := e.run(ctx, 2*time.Second, "systemctl", "is-active", s)
		buf.WriteString(fmt.Sprintf("Service %s: %s\n", s, status))
	}
	buf.WriteString("\n")

	if resolv, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		buf.WriteString("--- DNS Resolv.conf ---\n")
		buf.Write(resolv)
		buf.WriteString("\n")
	}

	return TruncateDiagnostics(SanitizeDiagnostics(buf.String()), MaxDiagnosticBytes), nil
}

func (e *LinuxEngine) appendCmdOutput(ctx context.Context, buf *bytes.Buffer, header string, name string, args ...string) {
	buf.WriteString(header + "\n")
	out, err := e.run(ctx, 3*time.Second, name, args...)
	if err != nil && out == "" {
		buf.WriteString(fmt.Sprintf("[error executing %s: %v]\n", name, err))
	} else {
		buf.WriteString(out + "\n")
	}
	buf.WriteString("\n")
}
