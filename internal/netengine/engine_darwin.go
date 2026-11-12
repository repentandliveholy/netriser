//go:build darwin

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
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

type DarwinEngine struct {
	cfg    *config.Config
	runner CommandRunner
}

func NewEngine(cfg *config.Config) NetworkEngine {
	return NewEngineWithRunner(cfg, nil)
}

func NewEngineWithRunner(cfg *config.Config, runner CommandRunner) NetworkEngine {
	ConfigureOverlays(cfg)
	if runner == nil {
		runner = &DefaultCommandRunner{}
	}
	return &DarwinEngine{cfg: cfg, runner: runner}
}

func (e *DarwinEngine) run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return e.runner.Run(ctx, name, args...)
}

func (e *DarwinEngine) DetectBaseline(ctx context.Context) (Baseline, error) {
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

	// Query routing table on macOS: route -n get default
	out, err := e.run(ctx, 3*time.Second, "route", "-n", "get", "default")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "gateway:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 && b.Gateway == "" {
					b.Gateway = parts[1]
				}
			} else if strings.HasPrefix(line, "interface:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					iface := parts[1]
					if !IsIgnoredInterface(iface) && b.Interface == "" {
						b.Interface = iface
					}
				}
			}
		}
	}

	// Fallback interface scan if default route was missing/hijacked
	if b.Interface == "" {
		for _, cand := range []string{"en0", "en1", "en2", "en7", "en8"} {
			ip := e.getDarwinInterfaceIPv4(ctx, cand)
			if ip != "" {
				b.Interface = cand
				b.IP = ip
				break
			}
		}
	}

	if b.Interface != "" && b.IP == "" {
		b.IP = e.getDarwinInterfaceIPv4(ctx, b.Interface)
	}

	if b.Gateway == "" && saved.Gateway != "" {
		b.Gateway = saved.Gateway
	}

	if b.IsValid() && b.Gateway != "" {
		_ = SaveBaseline(e.cfg.StateDir, b)
	}

	if !b.IsValid() {
		return b, fmt.Errorf("unable to detect valid physical network baseline on macOS: %+v", b)
	}
	return b, nil
}

func (e *DarwinEngine) getDarwinInterfaceIPv4(ctx context.Context, iface string) string {
	out, err := e.run(ctx, 2*time.Second, "ifconfig", iface)
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := net.ParseIP(fields[1])
				if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
		}
	}
	return ""
}

func (e *DarwinEngine) ApplyPolicyRouting(ctx context.Context, b Baseline) error {
	// On macOS, ensure physical default route exists
	if b.Gateway != "" {
		_, err := e.run(ctx, 2*time.Second, "route", "-n", "change", "default", b.Gateway)
		if err != nil {
			_, err = e.run(ctx, 2*time.Second, "route", "-n", "add", "default", b.Gateway)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *DarwinEngine) RemovePolicyRouting(ctx context.Context, b Baseline) error {
	return nil
}

func (e *DarwinEngine) SurgicalCleanRoutes(ctx context.Context, b Baseline) ([]ActionResult, error) {
	var actions []ActionResult

	// 1. Remove rogue default routes and NetBird /1 routes on mesh interfaces
	out, err := e.run(ctx, 3*time.Second, "netstat", "-rn", "-f", "inet")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				dest := fields[0]
				gw := fields[1]
				iface := fields[3]

				overlay := IsMeshInterface(iface)
				// Detect rogue /1 half-space routes (0/1 or 128.0/1) on overlays
				// recovery may touch; full-tunnel VPNs need allow_vpn_bypass.
				if isDarwinHalfRoute(dest) && actionableUnixOverlay(e.cfg, iface) {
					res := ActionResult{
						Type:        ActionCleanRoute,
						Target:      fmt.Sprintf("%s via %s", dest, iface),
						Status:      ActionExecuted,
						Description: fmt.Sprintf("Removed rogue /1 route %s on mesh device %s", dest, iface),
					}
					if _, rErr := e.run(ctx, 2*time.Second, "route", "-n", "delete", dest); rErr != nil {
						res.Status = ActionFailed
						res.Error = rErr.Error()
					}
					actions = append(actions, res)
				} else if dest == "default" && !e.cfg.IsAllowedDefaultInterface(iface) &&
					((overlay && actionableUnixOverlay(e.cfg, iface)) || (!overlay && b.Gateway != "" && gw != b.Gateway && !strings.HasPrefix(gw, "link#"))) {
					res := ActionResult{
						Type:        ActionCleanRoute,
						Target:      fmt.Sprintf("default via %s (%s)", gw, iface),
						Status:      ActionExecuted,
						Description: fmt.Sprintf("Removed rogue default route on device %s (gateway %s)", iface, gw),
					}
					_, _ = e.run(ctx, 2*time.Second, "route", "-n", "delete", "default", gw)
					if _, rErr := e.run(ctx, 2*time.Second, "route", "-n", "delete", "default"); rErr != nil {
						res.Status = ActionFailed
						res.Error = rErr.Error()
					}
					actions = append(actions, res)
				}
			}
		}
	}

	// 2. Re-assert physical interface link UP and default route
	if b.Interface != "" {
		_, _ = e.run(ctx, 2*time.Second, "ifconfig", b.Interface, "up")
	}
	if b.Gateway != "" {
		res := ActionResult{
			Type:        ActionRestoreRoute,
			Target:      fmt.Sprintf("default via %s", b.Gateway),
			Status:      ActionExecuted,
			Description: fmt.Sprintf("Re-asserted default route via %s on %s", b.Gateway, b.Interface),
		}
		_, cErr := e.run(ctx, 2*time.Second, "route", "-n", "change", "default", b.Gateway)
		if cErr != nil {
			if _, aErr := e.run(ctx, 2*time.Second, "route", "-n", "add", "default", b.Gateway); aErr != nil {
				res.Status = ActionFailed
				res.Error = aErr.Error()
			}
		}
		actions = append(actions, res)
	}

	// 3. Flush DNS cache
	_, _ = e.run(ctx, 2*time.Second, "dscacheutil", "-flushcache")
	_, _ = e.run(ctx, 2*time.Second, "killall", "-HUP", "mDNSResponder")

	return actions, nil
}

func isDarwinHalfRoute(dest string) bool {
	return dest == "0/1" || dest == "128.0/1" || dest == "0.0.0.0/1" || dest == "128.0.0.0/1"
}

// darwinRogueRoutes lists default and /1 routes of overlays recovery may touch.
func (e *DarwinEngine) darwinRogueRoutes(ctx context.Context) []DarwinRouteEntry {
	out, err := e.run(ctx, 3*time.Second, "netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil
	}
	var rogue []DarwinRouteEntry
	for _, r := range ParseDarwinNetstat(out) {
		if (r.Destination == "default" || isDarwinHalfRoute(r.Destination)) && actionableUnixOverlay(e.cfg, r.Interface) {
			rogue = append(rogue, r)
		}
	}
	return rogue
}

// RogueDefaultRoutes implements RogueRouteDetector.
// darwinRogueRoutes already excludes allowed_default_interfaces.
func (e *DarwinEngine) RogueDefaultRoutes(ctx context.Context) ([]string, error) {
	var out []string
	for _, r := range e.darwinRogueRoutes(ctx) {
		out = append(out, r.Destination+" on "+r.Interface)
	}
	return out, nil
}

// QuarantineMeshServices requires current evidence: an overlay that recovery
// may touch publishes a default or /1 route. macOS VPN clients share utun
// interface names, so the known NetBird and Tailscale clients are disconnected.
func (e *DarwinEngine) QuarantineMeshServices(ctx context.Context) ([]ActionResult, error) {
	var actions []ActionResult
	rogue := e.darwinRogueRoutes(ctx)
	if len(rogue) == 0 {
		return []ActionResult{{Type: ActionQuarantineService, Target: "all", Status: ActionSkipped, Description: "No overlay route evidence; preserving overlays"}}, nil
	}

	// 1. NetBird down: cleanly release exit-node routes and interface
	for _, nbCli := range []string{
		"/opt/homebrew/bin/netbird",
		"/usr/local/bin/netbird",
		"netbird",
	} {
		if _, err := os.Stat(nbCli); err == nil || nbCli == "netbird" {
			_, err := e.run(ctx, 3*time.Second, nbCli, "down")
			if err == nil {
				actions = append(actions, ActionResult{
					Type:        ActionQuarantineService,
					Target:      "netbird",
					Status:      ActionExecuted,
					Description: "Executed netbird down to release exit-node",
				})
				break
			}
		}
	}

	// 2. Tailscale: cleanly disconnect native macOS VPN service via scutil --nc
	_, err := e.run(ctx, 3*time.Second, "scutil", "--nc", "stop", "Tailscale")
	if err == nil {
		actions = append(actions, ActionResult{
			Type:        ActionQuarantineService,
			Target:      "tailscaled",
			Status:      ActionExecuted,
			Description: "Executed scutil --nc stop Tailscale",
		})
	}
	for _, tsCli := range []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/local/bin/tailscale"} {
		if _, err := os.Stat(tsCli); err == nil {
			_, _ = e.run(ctx, 2*time.Second, tsCli, "down")
			break
		}
	}

	// 3. Delete the rogue /1 routes found above
	for _, r := range rogue {
		if isDarwinHalfRoute(r.Destination) {
			_, _ = e.run(ctx, 2*time.Second, "route", "-n", "delete", r.Destination)
		}
	}

	// 4. Flush macOS DNS cache
	_, _ = e.run(ctx, 2*time.Second, "dscacheutil", "-flushcache")
	_, _ = e.run(ctx, 2*time.Second, "killall", "-HUP", "mDNSResponder")

	return actions, nil
}

func (e *DarwinEngine) RestoreMeshServices(ctx context.Context, services []string) ([]ActionResult, error) {
	var actions []ActionResult

	for _, s := range services {
		switch s {
		case "netbird", "netbird-client":
			for _, nbCli := range []string{
				"/opt/homebrew/bin/netbird",
				"/usr/local/bin/netbird",
				"netbird",
			} {
				if _, err := os.Stat(nbCli); err == nil || nbCli == "netbird" {
					res := ActionResult{
						Type:        ActionRestoreService,
						Target:      s,
						Status:      ActionExecuted,
						Description: "Executed netbird up",
					}
					if _, err := e.run(ctx, 5*time.Second, nbCli, "up"); err != nil {
						res.Status = ActionFailed
						res.Error = err.Error()
					}
					actions = append(actions, res)
					break
				}
			}

		case "tailscaled":
			res := ActionResult{
				Type:        ActionRestoreService,
				Target:      s,
				Status:      ActionExecuted,
				Description: "Executed scutil --nc start Tailscale",
			}
			if _, err := e.run(ctx, 3*time.Second, "scutil", "--nc", "start", "Tailscale"); err != nil {
				res.Status = ActionFailed
				res.Error = err.Error()
			}
			actions = append(actions, res)
			for _, tsCli := range []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/local/bin/tailscale"} {
				if _, err := os.Stat(tsCli); err == nil {
					_, _ = e.run(ctx, 3*time.Second, tsCli, "up")
					break
				}
			}

		default:
			actions = append(actions, ActionResult{
				Type:        ActionRestoreService,
				Target:      s,
				Status:      ActionSkipped,
				Description: fmt.Sprintf("Service %s not managed by native macOS launchd", s),
			})
		}
	}

	// Flush DNS cache
	_, _ = e.run(ctx, 2*time.Second, "dscacheutil", "-flushcache")
	_, _ = e.run(ctx, 2*time.Second, "killall", "-HUP", "mDNSResponder")

	return actions, nil
}

func (e *DarwinEngine) RestartNetworkStack(ctx context.Context, b Baseline) error {
	if b.Interface != "" {
		_, _ = e.run(ctx, 5*time.Second, "ipconfig", "set", b.Interface, "DHCP")
	}

	// Delete rogue /1 routes
	for _, half := range []string{"0/1", "128.0/1", "0.0.0.0/1", "128.0.0.0/1"} {
		_, _ = e.run(ctx, 2*time.Second, "route", "-n", "delete", half)
	}

	// Flush DNS cache
	_, _ = e.run(ctx, 2*time.Second, "dscacheutil", "-flushcache")
	_, _ = e.run(ctx, 2*time.Second, "killall", "-HUP", "mDNSResponder")

	// Re-assert default route
	if b.Gateway != "" {
		_, err := e.run(ctx, 2*time.Second, "route", "-n", "change", "default", b.Gateway)
		if err != nil {
			_, _ = e.run(ctx, 2*time.Second, "route", "-n", "add", "default", b.Gateway)
		}
	}
	return nil
}

func (e *DarwinEngine) EmergencyReboot(ctx context.Context, reason string) error {
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

	_, _ = e.run(ctx, 5*time.Second, "sync")
	_, _ = e.run(ctx, 5*time.Second, "shutdown", "-r", "now")
	return nil
}

func (e *DarwinEngine) SimulateHijackSession(ctx context.Context, b Baseline, rollbackDuration time.Duration) (SimulationSession, error) {
	return StartDetachedSimulation(ctx, e.cfg, e.runner, b, rollbackDuration)
}

func (e *DarwinEngine) SimulateHijack(ctx context.Context, b Baseline, rollbackDuration time.Duration) (func(), error) {
	session, err := e.SimulateHijackSession(ctx, b, rollbackDuration)
	if err != nil {
		return nil, err
	}
	return func() {
		_ = session.Disarm()
	}, nil
}

func (e *DarwinEngine) DumpDiagnostics(ctx context.Context, b Baseline) (string, error) {
	var buf bytes.Buffer
	buf.WriteString("=== NETRISER DIAGNOSTIC REPORT (MACOS) ===\n")
	buf.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("Physical Baseline: %s\n\n", b.String()))

	e.appendDarwinCmdOutput(ctx, &buf, "--- Routing Table (netstat -rn -f inet) ---", "netstat", "-rn", "-f", "inet")
	e.appendDarwinCmdOutput(ctx, &buf, "--- Default Route (route -n get default) ---", "route", "-n", "get", "default")
	e.appendDarwinCmdOutput(ctx, &buf, "--- Network Interfaces (ifconfig) ---", "ifconfig")
	e.appendDarwinCmdOutput(ctx, &buf, "--- DNS Configuration (scutil --dns) ---", "scutil", "--dns")

	return TruncateDiagnostics(SanitizeDiagnostics(buf.String()), MaxDiagnosticBytes), nil
}

func (e *DarwinEngine) appendDarwinCmdOutput(ctx context.Context, buf *bytes.Buffer, header string, name string, args ...string) {
	buf.WriteString(header + "\n")
	out, err := e.run(ctx, 5*time.Second, name, args...)
	if err != nil && out == "" {
		buf.WriteString(fmt.Sprintf("[error executing %s: %v]\n", name, err))
	} else {
		buf.WriteString(out + "\n")
	}
	buf.WriteString("\n")
}
