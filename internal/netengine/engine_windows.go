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
	"regexp"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

type WindowsEngine struct {
	cfg    *config.Config
	runner CommandRunner
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

// Regex matching virtual/mesh Windows adapter names or descriptions
var windowsOverlayRegex = regexp.MustCompile(`(?i)(netbird|wt[0-9]|zerotier|zt[a-z0-9]|tailscale|nebula|wireguard|wintun|tap-windows|openvpn|hyper-v|vethernet)`)

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

	saved, _ := LoadSavedBaseline(e.cfg.StateDir)
	if b.Interface == "" && saved.Interface != "" {
		b.Interface = saved.Interface
		if b.Gateway == "" {
			b.Gateway = saved.Gateway
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

	// Detect and remove rogue default routes on overlay interfaces
	psScript := `
$removed = @()
Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $alias = $_.InterfaceAlias
    $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
    $desc = if ($adapter) { $adapter.InterfaceDescription } else { "" }
    if ($alias -match '(?i)(netbird|wt|zerotier|zt|tailscale|nebula|wireguard|wintun|tap)' -or $desc -match '(?i)(netbird|zerotier|tailscale|nebula|wintun|tap)') {
        Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $alias -Confirm:$false -ErrorAction SilentlyContinue
        $removed += "Removed rogue 0.0.0.0/0 on overlay interface $alias"
    }
}
# Also remove /1 rogue half-routes
foreach ($half in @('0.0.0.0/1', '128.0.0.0/1')) {
    Get-NetRoute -DestinationPrefix $half -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        $alias = $_.InterfaceAlias
        Remove-NetRoute -DestinationPrefix $half -InterfaceAlias $alias -Confirm:$false -ErrorAction SilentlyContinue
        $removed += "Removed rogue $half on $alias"
    }
}
$removed | Out-String
`
	out, err := e.runPowerShell(ctx, 5*time.Second, psScript)
	if err == nil && out != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				actions = append(actions, ActionResult{
					Type:        ActionCleanRoute,
					Target:      line,
					Status:      ActionExecuted,
					Description: line,
				})
			}
		}
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

func (e *WindowsEngine) QuarantineMeshServices(ctx context.Context) ([]ActionResult, error) {
	var actions []ActionResult

	for _, s := range e.cfg.MonitoredServices {
		psScript := fmt.Sprintf(`
$svc = Get-Service -Name '%s' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Stop-Service -Name '%s' -Force -ErrorAction SilentlyContinue
    Write-Output "STOPPED"
}
`, s, s)
		out, err := e.runPowerShell(ctx, 8*time.Second, psScript)
		if err == nil && strings.Contains(out, "STOPPED") {
			actions = append(actions, ActionResult{
				Type:        ActionQuarantineService,
				Target:      s,
				Status:      ActionExecuted,
				Description: fmt.Sprintf("Stopped Windows service: %s", s),
			})
		}
	}

	// Disable overlay adapters
	disableScript := `
Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceAlias -match '(?i)(netbird|wt|zerotier|zt|tailscale|nebula|wintun)' -or
    $_.InterfaceDescription -match '(?i)(netbird|zerotier|tailscale|nebula|wintun)'
} | ForEach-Object {
    Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output $_.Name
}
`
	out, err := e.runPowerShell(ctx, 10*time.Second, disableScript)
	if err == nil && out != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				actions = append(actions, ActionResult{
					Type:        ActionCleanRoute,
					Target:      line,
					Status:      ActionExecuted,
					Description: fmt.Sprintf("Disabled adapter: %s", line),
				})
			}
		}
	}

	return actions, nil
}

func (e *WindowsEngine) RestoreMeshServices(ctx context.Context, services []string) ([]ActionResult, error) {
	var actions []ActionResult
	for _, s := range services {
		if s == "" {
			continue
		}
		psScript := fmt.Sprintf(`Start-Service -Name '%s' -ErrorAction SilentlyContinue`, s)
		res := ActionResult{
			Type:        ActionRestoreService,
			Target:      s,
			Status:      ActionExecuted,
			Description: fmt.Sprintf("Started service: %s", s),
		}
		if _, err := e.runPowerShell(ctx, 8*time.Second, psScript); err != nil {
			res.Status = ActionFailed
			res.Error = err.Error()
		}
		actions = append(actions, res)
	}
	_, _ = e.runPowerShell(ctx, 5*time.Second, `Get-NetAdapter | Where-Object { $_.InterfaceDescription -match '(?i)(netbird|zerotier|tailscale|nebula|wintun)' } | Enable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue`)
	return actions, nil
}

func (e *WindowsEngine) RestartNetworkStack(ctx context.Context, b Baseline) error {
	if b.Interface != "" {
		psScript := fmt.Sprintf(`Restart-NetAdapter -Name '%s' -Confirm:$false -ErrorAction SilentlyContinue`, b.Interface)
		_, _ = e.runPowerShell(ctx, 10*time.Second, psScript)
	}
	_, _ = e.runCmd(ctx, 5*time.Second, "ipconfig.exe", "/renew")
	return nil
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
