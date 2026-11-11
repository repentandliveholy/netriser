//go:build windows

package netengine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

type WindowsEngine struct {
	cfg    *config.Config
	runner CommandRunner

	// Overlay routes removed by stage 1. Route cleanup erases the evidence that
	// stage 2 needs (and cannot lift a WireGuard kill-switch), so the daemon
	// remembers the owners of recently removed rogue routes.
	mu    sync.Mutex
	rogue map[string]windowsRogueEvidence
}

type windowsRogueEvidence struct {
	route WindowsRoute
	seen  time.Time
}

const windowsRogueEvidenceTTL = 10 * time.Minute

// windowsDefaultRoutesScript lists default and split-default IPv4 routes as
// "alias|prefix|effective metric|adapter description" lines. The effective
// metric is what Windows compares: route metric plus interface metric.
const windowsDefaultRoutesScript = `
foreach ($p in @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1')) {
    Get-NetRoute -DestinationPrefix $p -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        $adapter = Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue
        $desc = if ($adapter) { $adapter.InterfaceDescription } else { '' }
        $ipif = Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $metric = if ($ipif) { [int]$_.RouteMetric + [int]$ipif.InterfaceMetric } else { -1 }
        Write-Output "$($_.InterfaceAlias)|$($_.DestinationPrefix)|$metric|$desc"
    }
}
# A prefix without routes (usually the /1 halves) leaves $? false, which makes
# powershell.exe -Command exit with 1 although the listing is complete.
exit 0
`

func (e *WindowsEngine) rogueRoutes(ctx context.Context) ([]WindowsRoute, error) {
	out, err := e.runPowerShell(ctx, 8*time.Second, windowsDefaultRoutesScript)
	if err != nil {
		return nil, err
	}
	return WindowsRogueRoutes(ParseWindowsRoutes(out), e.cfg.IsAllowedDefaultInterface), nil
}

func (e *WindowsEngine) rememberRogue(routes []WindowsRoute) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rogue == nil {
		e.rogue = map[string]windowsRogueEvidence{}
	}
	for _, r := range routes {
		e.rogue[r.Alias] = windowsRogueEvidence{route: r, seen: time.Now()}
	}
}

// rogueOwners merges current rogue routes with recently removed ones, one per
// interface, and forgets expired evidence.
func (e *WindowsEngine) rogueOwners(current []WindowsRoute) []WindowsRoute {
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[string]bool{}
	var owners []WindowsRoute
	for _, r := range current {
		if !seen[r.Alias] {
			seen[r.Alias] = true
			owners = append(owners, r)
		}
	}
	for alias, ev := range e.rogue {
		if time.Since(ev.seen) > windowsRogueEvidenceTTL || e.cfg.IsAllowedDefaultInterface(alias) {
			delete(e.rogue, alias)
			continue
		}
		if !seen[alias] {
			seen[alias] = true
			owners = append(owners, ev.route)
		}
	}
	return owners
}

func (e *WindowsEngine) forgetRogue(alias string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rogue, alias)
}

func NewEngine(cfg *config.Config) NetworkEngine {
	return NewEngineWithRunner(cfg, nil)
}

func NewEngineWithRunner(cfg *config.Config, runner CommandRunner) NetworkEngine {
	if runner == nil {
		runner = &DefaultCommandRunner{}
	}
	return &WindowsEngine{cfg: cfg, runner: runner}
}

func (e *WindowsEngine) runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return e.runner.Run(ctx, name, args...)
}

func (e *WindowsEngine) runPowerShell(ctx context.Context, timeout time.Duration, script string) (string, error) {
	return e.runCmd(ctx, timeout, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func (e *WindowsEngine) DetectBaseline(ctx context.Context) (Baseline, error) {
	var b Baseline
	b.DetectedAt = time.Now()

	if e.cfg.ManagementInterface != "" {
		b.Interface = e.cfg.ManagementInterface
	}
	if e.cfg.ManagementGateway != "" {
		b.Gateway = e.cfg.ManagementGateway
	}
	if b.Interface != "" || b.Gateway != "" {
		b.Source = BaselineSourceConfig
	}

	// A known uplink stays authoritative while it is disabled or has lost its
	// address, so stage 3 can bring it back (HasKnownInterface).
	saved, _ := LoadSavedBaseline(e.cfg.StateDir)
	if b.Interface == "" && saved.Interface != "" {
		b.Interface = saved.Interface
		if b.Gateway == "" {
			b.Gateway = saved.Gateway
		}
		if b.Source == "" {
			b.Source = BaselineSourceCached
		}
	}

	// PowerShell query for default routes on physical adapters
	psScript := `
Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $alias = $_.InterfaceAlias
    $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
    $desc = if ($adapter) { $adapter.InterfaceDescription } else { "" }
    $status = if ($adapter) { $adapter.Status } else { "" }
    Write-Output "$alias|$($_.NextHop)|$desc|$status"
}
`
	out, err := e.runPowerShell(ctx, 5*time.Second, psScript)
	if err == nil && out != "" {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), "|")
			if len(parts) >= 2 {
				alias := strings.TrimSpace(parts[0])
				nextHop := strings.TrimSpace(parts[1])
				desc := ""
				status := ""
				if len(parts) >= 3 {
					desc = strings.TrimSpace(parts[2])
				}
				if len(parts) >= 4 {
					status = strings.TrimSpace(parts[3])
				}

				if windowsOverlayRegex.MatchString(alias) || windowsOverlayRegex.MatchString(desc) {
					continue
				}

				if b.Interface == "" {
					b.Interface = alias
				}
				if b.Gateway == "" && nextHop != "" && nextHop != "0.0.0.0" {
					b.Gateway = nextHop
				}
				if status == "Up" {
					break
				}
			}
		}
	}

	// Fallback to route.exe print 0.0.0.0 if powershell had no output
	if b.Interface == "" || b.Gateway == "" {
		routeOut, _ := e.runCmd(ctx, 3*time.Second, "route.exe", "print", "0.0.0.0")
		scanner := bufio.NewScanner(strings.NewReader(routeOut))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				gw := fields[2]
				ip := fields[3]
				if b.Gateway == "" && gw != "0.0.0.0" {
					b.Gateway = gw
				}
				if b.IP == "" {
					b.IP = ip
				}
			}
		}
	}

	// If Interface is still missing but IP is known, discover InterfaceAlias by IPAddress
	if b.Interface == "" && b.IP != "" {
		aliasScript := fmt.Sprintf(`(Get-NetIPAddress -IPAddress '%s' -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceAlias`, b.IP)
		aliasOut, _ := e.runPowerShell(ctx, 3*time.Second, aliasScript)
		b.Interface = strings.TrimSpace(aliasOut)
	}

	// Detect current IP for chosen InterfaceAlias if unset
	if b.Interface != "" && b.IP == "" {
		ipScript := fmt.Sprintf(`(Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress`, b.Interface)
		ipOut, _ := e.runPowerShell(ctx, 3*time.Second, ipScript)
		if ipOut != "" && net.ParseIP(ipOut) != nil {
			b.IP = ipOut
		}
	}

	if b.Gateway == "" && saved.Gateway != "" {
		b.Gateway = saved.Gateway
	}

	if b.IsValid() && b.Gateway != "" {
		_ = SaveBaseline(e.cfg.StateDir, b)
	}

	if !b.IsValid() {
		return b, fmt.Errorf("unable to detect valid physical network baseline on Windows: %+v", b)
	}
	return b, nil
}

func (e *WindowsEngine) ApplyPolicyRouting(ctx context.Context, b Baseline) error {
	if !b.IsValid() {
		return fmt.Errorf("cannot apply policy routing: invalid baseline %+v", b)
	}
	// On Windows, enforce interface metric to 10 for physical adapter
	psScript := fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -InterfaceMetric 10 -ErrorAction SilentlyContinue`, b.Interface)
	_, _ = e.runPowerShell(ctx, 3*time.Second, psScript)

	// If gateway is known, ensure persistent route or route entry exists with low metric
	if b.Gateway != "" {
		_, _ = e.runPowerShell(ctx, 3*time.Second, fmt.Sprintf(`
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '%s' -NextHop '%s' -ErrorAction SilentlyContinue
if (-not $route) {
    New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '%s' -NextHop '%s' -RouteMetric 10 -ErrorAction SilentlyContinue
}
`, b.Interface, b.Gateway, b.Interface, b.Gateway))
	}
	return nil
}

func (e *WindowsEngine) RemovePolicyRouting(ctx context.Context, b Baseline) error {
	if b.Interface != "" {
		psScript := fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -AutomaticMetric Enabled -ErrorAction SilentlyContinue`, b.Interface)
		_, _ = e.runPowerShell(ctx, 3*time.Second, psScript)
	}
	return nil
}

func (e *WindowsEngine) SurgicalCleanRoutes(ctx context.Context, b Baseline) ([]ActionResult, error) {
	var actions []ActionResult

	// Remove default and split-default routes published by VPN/mesh adapters,
	// except interfaces listed in allowed_default_interfaces.
	rogue, err := e.rogueRoutes(ctx)
	if err != nil {
		actions = append(actions, ActionResult{Type: ActionCleanRoute, Target: "routes", Status: ActionFailed, Error: err.Error(), Description: "Could not list default routes"})
	}
	e.rememberRogue(rogue)
	for _, r := range rogue {
		// A WireGuard full tunnel owns the route and, with its kill-switch,
		// blocks untunneled traffic that route cleanup cannot restore (while
		// still permitting DNS to the tunnel's resolvers). Stop the tunnel.
		if r.IsWindowsWireGuard() && e.cfg.AllowServiceQuarantine {
			if act, ok := e.stopOverlayService(ctx, r); ok {
				actions = append(actions, act)
				continue
			}
		}
		script := fmt.Sprintf(`Remove-NetRoute -DestinationPrefix %s -InterfaceAlias %s -Confirm:$false -ErrorAction Stop`, psQuote(r.Prefix), psQuote(r.Alias))
		act := ActionResult{
			Type:        ActionCleanRoute,
			Target:      r.Prefix + " on " + r.Alias,
			Status:      ActionExecuted,
			Description: fmt.Sprintf("Removed rogue %s on overlay interface %s", r.Prefix, r.Alias),
		}
		if _, err := e.runPowerShell(ctx, 5*time.Second, script); err != nil {
			act.Status, act.Error = ActionFailed, err.Error()
		}
		actions = append(actions, act)
	}

	// Re-assert physical adapter state and default route
	if b.Interface != "" {
		enableScript := fmt.Sprintf(`
$adapter = Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue
if ($adapter -and $adapter.Status -ne 'Up') {
    Enable-NetAdapter -Name '%s' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "ENABLED"
}
`, b.Interface, b.Interface)
		out, err := e.runPowerShell(ctx, 5*time.Second, enableScript)
		if err == nil && strings.Contains(out, "ENABLED") {
			actions = append(actions, ActionResult{
				Type:        ActionRestartStack,
				Target:      b.Interface,
				Status:      ActionExecuted,
				Description: fmt.Sprintf("Restored physical network adapter state to Enabled/Up on %s", b.Interface),
			})
		}

		if b.Gateway != "" {
			reassertScript := fmt.Sprintf(`
$exists = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '%s' -NextHop '%s' -ErrorAction SilentlyContinue
if (-not $exists) {
    New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias '%s' -NextHop '%s' -RouteMetric 10 -Confirm:$false -ErrorAction SilentlyContinue
}
Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -InterfaceMetric 10 -ErrorAction SilentlyContinue
`, b.Interface, b.Gateway, b.Interface, b.Gateway, b.Interface)
			_, _ = e.runPowerShell(ctx, 5*time.Second, reassertScript)
			actions = append(actions, ActionResult{
				Type:        ActionRestoreRoute,
				Target:      fmt.Sprintf("0.0.0.0/0 on %s via %s", b.Interface, b.Gateway),
				Status:      ActionExecuted,
				Description: fmt.Sprintf("Re-asserted physical default route via %s on %s with metric 10", b.Gateway, b.Interface),
			})
		}
	}

	return actions, nil
}

// QuarantineMeshServices stops only the overlays that published a rogue
// default route (now or during recent route cleanup). Stopping a WireGuard
// tunnel service also removes its kill-switch firewall rules. Overlays without
// a known service are contained by disabling their adapter.
func (e *WindowsEngine) QuarantineMeshServices(ctx context.Context) ([]ActionResult, error) {
	current, err := e.rogueRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot list default routes: %w", err)
	}
	owners := e.rogueOwners(current)
	if len(owners) == 0 {
		return nil, fmt.Errorf("no rogue overlay default route detected; preserving overlays")
	}

	var actions []ActionResult
	for _, r := range owners {
		actions = append(actions, e.containOverlay(ctx, r))
	}
	return actions, nil
}

// stopOverlayService stops the service owning an overlay interface. ok is
// false when the service is unknown, missing or could not be stopped.
func (e *WindowsEngine) stopOverlayService(ctx context.Context, r WindowsRoute) (ActionResult, bool) {
	svc := WindowsOverlayService(r)
	if svc == "" {
		return ActionResult{}, false
	}
	script := fmt.Sprintf(`
$svc = Get-Service -Name %s -ErrorAction SilentlyContinue
if (-not $svc) { Write-Output 'MISSING' }
elseif ($svc.Status -ne 'Running') { Write-Output 'NOT_RUNNING' }
else { Stop-Service -Name %s -Force -ErrorAction Stop; Write-Output 'STOPPED' }
`, psQuote(svc), psQuote(svc))
	out, err := e.runPowerShell(ctx, 15*time.Second, script)
	switch {
	case err != nil:
		return ActionResult{Type: ActionQuarantineService, Target: svc, Status: ActionFailed, Error: err.Error(), Description: "Failed to stop overlay service " + svc}, false
	case strings.Contains(out, "STOPPED"):
		e.forgetRogue(r.Alias)
		return ActionResult{Type: ActionQuarantineService, Target: svc, Status: ActionExecuted, Description: fmt.Sprintf("Stopped service %s publishing rogue %s on %s", svc, r.Prefix, r.Alias)}, true
	case strings.Contains(out, "NOT_RUNNING"):
		e.forgetRogue(r.Alias)
		return ActionResult{Type: ActionQuarantineService, Target: svc, Status: ActionNotNeeded, Description: "Overlay service already stopped: " + svc}, true
	}
	return ActionResult{}, false
}

// containOverlay stops the owning service, or disables the adapter when the
// service is unknown, missing or could not be stopped.
func (e *WindowsEngine) containOverlay(ctx context.Context, r WindowsRoute) ActionResult {
	if act, ok := e.stopOverlayService(ctx, r); ok {
		return act
	}
	target := WindowsAdapterTargetPrefix + r.Alias
	script := fmt.Sprintf(`Disable-NetAdapter -Name %s -Confirm:$false -ErrorAction Stop`, psQuote(r.Alias))
	act := ActionResult{Type: ActionQuarantineService, Target: target, Status: ActionExecuted, Description: fmt.Sprintf("Disabled overlay adapter %s publishing rogue %s", r.Alias, r.Prefix)}
	if _, err := e.runPowerShell(ctx, 10*time.Second, script); err != nil {
		act.Status, act.Error = ActionFailed, err.Error()
	} else {
		e.forgetRogue(r.Alias)
	}
	return act
}

func (e *WindowsEngine) RestoreMeshServices(ctx context.Context, services []string) ([]ActionResult, error) {
	var actions []ActionResult
	var firstErr error
	for _, s := range services {
		if s == "" {
			continue
		}
		var script string
		res := ActionResult{Type: ActionRestoreService, Target: s, Status: ActionExecuted}
		// A service or adapter removed while quarantined has nothing to restore.
		if alias, ok := strings.CutPrefix(s, WindowsAdapterTargetPrefix); ok {
			script = fmt.Sprintf(`if (Get-NetAdapter -Name %s -ErrorAction SilentlyContinue) { Enable-NetAdapter -Name %s -Confirm:$false -ErrorAction Stop } else { Write-Output 'MISSING' }`, psQuote(alias), psQuote(alias))
			res.Description = "Enabled overlay adapter: " + alias
		} else {
			script = fmt.Sprintf(`if (Get-Service -Name %s -ErrorAction SilentlyContinue) { Start-Service -Name %s -ErrorAction Stop } else { Write-Output 'MISSING' }`, psQuote(s), psQuote(s))
			res.Description = "Started service: " + s
		}
		out, err := e.runPowerShell(ctx, 15*time.Second, script)
		switch {
		case err != nil:
			res.Status, res.Error = ActionFailed, err.Error()
			if firstErr == nil {
				firstErr = err
			}
		case strings.Contains(out, "MISSING"):
			res.Status, res.Description = ActionNotNeeded, "No longer installed; nothing to restore: "+s
		}
		actions = append(actions, res)
	}
	return actions, firstErr
}

// RestartNetworkStack brings the physical uplink back: it enables an adapter
// that was disabled (for example from the Network Connections window),
// otherwise restarts it, waits for a usable IPv4 address, renews DHCP if
// needed and restores the default route through the known gateway.
func (e *WindowsEngine) RestartNetworkStack(ctx context.Context, b Baseline) error {
	if b.Interface == "" {
		_, _ = e.runCmd(ctx, 15*time.Second, "ipconfig.exe", "/renew")
		return fmt.Errorf("physical interface unknown; renewed DHCP on all adapters")
	}
	out, err := e.runPowerShell(ctx, 40*time.Second, windowsUplinkRecoveryScript(b.Interface))
	if err != nil {
		return fmt.Errorf("recover adapter %s: %w", b.Interface, err)
	}
	if strings.Contains(out, "MISSING") {
		return fmt.Errorf("adapter %s not found", b.Interface)
	}
	if !strings.Contains(out, "UP ") {
		_, _ = e.runCmd(ctx, 15*time.Second, "ipconfig.exe", "/renew", b.Interface)
	}
	if b.Gateway != "" {
		_, _ = e.runPowerShell(ctx, 8*time.Second, windowsDefaultRouteScript(b.Interface, b.Gateway))
	}
	if !strings.Contains(out, "UP ") {
		return fmt.Errorf("adapter %s did not obtain a usable IPv4 address (%s)", b.Interface, strings.TrimSpace(out))
	}
	return nil
}

// windowsUplinkRecoveryScript enables or restarts an adapter and waits up to
// 25 seconds for it to be Up with a non-APIPA IPv4 address.
func windowsUplinkRecoveryScript(alias string) string {
	return fmt.Sprintf(`
$name = %s
$a = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
if (-not $a) { Write-Output 'MISSING'; return }
if ($a.Status -eq 'Disabled') {
    Enable-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop
    Write-Output 'ENABLED'
} else {
    Restart-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop
    Write-Output 'RESTARTED'
}
$deadline = (Get-Date).AddSeconds(25)
do {
    Start-Sleep -Milliseconds 500
    $a = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
    $ip = Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
} while ((-not $a -or $a.Status -ne 'Up' -or -not $ip) -and (Get-Date) -lt $deadline)
if ($a -and $a.Status -eq 'Up' -and $ip) { Write-Output "UP $($ip.IPAddress)" } else { Write-Output "STATUS $($a.Status)" }
`, psQuote(alias))
}

func windowsDefaultRouteScript(alias, gateway string) string {
	return fmt.Sprintf(`
if (-not (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias %s -NextHop %s -ErrorAction SilentlyContinue)) {
    New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias %s -NextHop %s -RouteMetric 10 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
`, psQuote(alias), psQuote(gateway), psQuote(alias), psQuote(gateway))
}

func (e *WindowsEngine) EmergencyReboot(ctx context.Context, reason string) error {
	if !e.cfg.EnableReboot {
		return fmt.Errorf("emergency reboot skipped: reboot is disabled in config")
	}

	panicLog := filepath.Join(e.cfg.StateDir, "panic_reboot_history.log")
	msg := fmt.Sprintf("[%s] EMERGENCY REBOOT TRIGGERED: %s\n", time.Now().Format("2006-01-02 15:04:05"), reason)
	_ = os.WriteFile(panicLog, []byte(msg), 0640)

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
	_, _ = e.runCmd(ctx, 10*time.Second, "shutdown.exe", "/r", "/t", "5", "/f", "/c", "NetRiser Emergency Reboot")
	return nil
}

func (e *WindowsEngine) SimulateHijackSession(ctx context.Context, b Baseline, rollbackDuration time.Duration) (SimulationSession, error) {
	return StartDetachedSimulation(ctx, e.cfg, e.runner, b, rollbackDuration)
}

func (e *WindowsEngine) SimulateHijack(ctx context.Context, b Baseline, rollbackDuration time.Duration) (func(), error) {
	session, err := e.SimulateHijackSession(ctx, b, rollbackDuration)
	if err != nil {
		return nil, err
	}
	return func() {
		_ = session.Disarm()
	}, nil
}

func (e *WindowsEngine) DumpDiagnostics(ctx context.Context, b Baseline) (string, error) {
	var buf bytes.Buffer
	buf.WriteString("=== NETRISER DIAGNOSTIC REPORT (WINDOWS) ===\n")
	buf.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("Physical Baseline: %s\n\n", b.String()))

	e.appendWinCmdOutput(ctx, &buf, "--- Routing Table (route print) ---", "route.exe", "print")
	e.appendWinCmdOutput(ctx, &buf, "--- IP Configuration (ipconfig /all) ---", "ipconfig.exe", "/all")

	buf.WriteString("--- NetAdapters Status ---\n")
	psAdapters, _ := e.runPowerShell(ctx, 5*time.Second, `Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed | Format-Table -AutoSize | Out-String`)
	buf.WriteString(psAdapters + "\n\n")

	buf.WriteString("--- Monitored Services Status ---\n")
	psServices, _ := e.runPowerShell(ctx, 5*time.Second, `Get-Service netbird, zerotier-one, Tailscale, nebula -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status | Format-Table -AutoSize | Out-String`)
	buf.WriteString(psServices + "\n\n")

	return TruncateDiagnostics(SanitizeDiagnostics(buf.String()), MaxDiagnosticBytes), nil
}

func (e *WindowsEngine) appendWinCmdOutput(ctx context.Context, buf *bytes.Buffer, header string, name string, args ...string) {
	buf.WriteString(header + "\n")
	out, err := e.runCmd(ctx, 5*time.Second, name, args...)
	if err != nil && out == "" {
		buf.WriteString(fmt.Sprintf("[error executing %s: %v]\n", name, err))
	} else {
		buf.WriteString(out + "\n")
	}
	buf.WriteString("\n")
}
