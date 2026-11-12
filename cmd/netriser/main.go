package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/service"
	"github.com/repentandliveholy/netriser/internal/updater"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

var (
	Version   = "1.3.2"
	Commit    = "unknown"
	BuildTime = "unknown"
)

type cliOptions struct {
	confPath          string
	verbose           bool
	jsonOutput        bool
	dryRun            bool
	version           bool
	help              bool
	force             bool
	checkOnly         bool
	updateURL         string
	installAutoUpdate string
	installReboot     string
	installObserve    string
	installVPNBypass  string
	installFullTunnel string
	nonInteractive    bool
	noRestart         bool
	saveAnswers       string
	answers           string
	commands          []string
}

func parseCLIArgs(args []string) cliOptions {
	var opts cliOptions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--auto-update="):
			opts.installAutoUpdate = strings.TrimPrefix(arg, "--auto-update=")
		case strings.HasPrefix(arg, "--enable-reboot="):
			opts.installReboot = strings.TrimPrefix(arg, "--enable-reboot=")
		case strings.HasPrefix(arg, "--observation-mode="):
			opts.installObserve = strings.TrimPrefix(arg, "--observation-mode=")
		case strings.HasPrefix(arg, "--allow-vpn-bypass="):
			opts.installVPNBypass = strings.TrimPrefix(arg, "--allow-vpn-bypass=")
		case strings.HasPrefix(arg, "--full-tunnel="):
			opts.installFullTunnel = strings.TrimPrefix(arg, "--full-tunnel=")
		case arg == "--non-interactive":
			opts.nonInteractive = true
		case arg == "--no-restart":
			opts.noRestart = true
		case strings.HasPrefix(arg, "--save-answers="):
			opts.saveAnswers = strings.TrimPrefix(arg, "--save-answers=")
		case strings.HasPrefix(arg, "--answers="):
			opts.answers = strings.TrimPrefix(arg, "--answers=")
		case arg == "-h" || arg == "--help":
			opts.help = true
		case arg == "-v" || arg == "--verbose":
			opts.verbose = true
		case arg == "--json":
			opts.jsonOutput = true
		case arg == "--dry-run":
			opts.dryRun = true
		case arg == "--force":
			opts.force = true
		case arg == "--check":
			opts.checkOnly = true
		case arg == "--update-url":
			if i+1 < len(args) {
				opts.updateURL = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--update-url="):
			opts.updateURL = strings.TrimPrefix(arg, "--update-url=")
		case arg == "--version" || arg == "-V":
			opts.version = true
		case arg == "-c" || arg == "--config":
			if i+1 < len(args) {
				opts.confPath = args[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--config="):
			opts.confPath = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-c="):
			opts.confPath = strings.TrimPrefix(arg, "-c=")
		case strings.HasPrefix(arg, "-"):
			// Unknown flag, ignore or keep
		default:
			opts.commands = append(opts.commands, arg)
		}
	}
	return opts
}

func printUsage() {
	fmt.Printf(`netriser v%s — Cross-Platform Network Monitoring & Auto-Remediation

Usage:
  netriser [flags] <command> [subcommand]

Commands:
  setup              Answer the installation questions again and apply them
  start              Start background watchdog service
  stop               Stop background watchdog service
  restart            Restart background watchdog service
  up                 Start watchdog service and enforce management policy routing
  down               Stop watchdog service and revert policy routing
  reboot [cmd]       Quickly toggle emergency reboot (on, off, enable, disable, status)
  observe [cmd]      Observation (read-only) mode: on, off, status
  status             Display structured status of baseline, canaries, and routes
  logs [N|all]       Show the last N log entries (default 50, including the rotated log)
  live               Show new log entries in real time (Ctrl+C to stop)
  run                Run in continuous background daemon / service mode
  check              Run one-shot connectivity check and auto-remediate if down
  autoupdate [cmd]   Automatic updates: on, off, status (default: on)
  update             Check for updates and self-update binary to latest release
  dry-run            Evaluate escalation plan without executing any network mutations
  check-config       Validate YAML configuration and physical baseline discovery
  diagnose           Generate and display deep diagnostic dump
  simulate-hijack    Safely test route hijack remediation (with 45s safety rollback)
  migrate            Preserve legacy configuration and state paths
  init-config        Create configuration; preserve existing settings unless overridden
                     (non-interactive; use 'setup' to be asked every question)
  service <cmd>      Manage OS service (install, uninstall, start, stop, restart, status)
  apply-policy       Enforce management policy routing (Table 200 on Linux)
  remove-policy      Remove custom management policy routing rules
  reset              Reset failure counter (preserves quarantine history)
  version            Print version information

Flags:
  -c, --config string   Path to YAML configuration file (default: OS standard)
  --json                Output results in structured JSON format to stdout
  --dry-run             Simulate actions without executing mutations (with 'check')
  --check               Check for updates without downloading or applying (with 'update')
  --force               Force reinstall latest version (with 'update')
  --update-url string   Override update server base URL (with 'update')
  --auto-update=bool    Select automatic updates (with 'init-config')
  --enable-reboot=bool  Select emergency reboot (with 'init-config')
  --observation-mode=bool  Log incidents only, no recovery (with 'setup', 'init-config')
  --allow-vpn-bypass=bool  Allow bypassing a full-tunnel VPN that cut the host off (with 'setup')
  --full-tunnel=bool    Whether this host routes all traffic through a VPN; false removes
                        any VPN or exit node that takes over the default route (with 'setup')
  --non-interactive     Ask no questions; apply only explicit settings (with 'setup')
  --save-answers=PATH   Ask the questions and save the answers without applying them (with 'setup')
  --answers=PATH        Apply previously saved answers without asking (with 'setup')
  --no-restart          Do not restart a running service after changes (with 'setup')
  -v, --verbose         Enable verbose console logging (routed to stderr with --json)
  -h, --help            Show this help message
  -V, --version         Print version information
`, Version)
}

func main() {
	opts := parseCLIArgs(os.Args[1:])

	if opts.help {
		printUsage()
		os.Exit(0)
	}

	if opts.version || (len(opts.commands) > 0 && opts.commands[0] == "version") {
		if opts.jsonOutput {
			fmt.Printf(`{"version":%q,"commit":%q,"build_time":%q}`+"\n", Version, Commit, BuildTime)
		} else {
			fmt.Printf("netriser version %s (commit: %s, built at: %s)\n", Version, Commit, BuildTime)
		}
		os.Exit(0)
	}

	cmd := "status"
	if len(opts.commands) > 0 {
		cmd = opts.commands[0]
	}

	if cmd == "migrate" {
		migrated, err := config.MigrateLegacy(opts.confPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Migration failed: %v\n", err)
			os.Exit(1)
		}
		if migrated {
			fmt.Println("Legacy mesh-watchdog configuration and state paths preserved.")
		} else {
			fmt.Println("No legacy configuration to migrate.")
		}
		return
	}
	if cmd == "setup" || cmd == "configure" {
		os.Exit(runSetup(opts))
	}
	if cmd == "init-config" {
		autoUpdate, err := optionalBool(opts.installAutoUpdate)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid --auto-update:", err)
			os.Exit(1)
		}
		reboot, err := optionalBool(opts.installReboot)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid --enable-reboot:", err)
			os.Exit(1)
		}
		observe, err := optionalBool(opts.installObserve)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid --observation-mode:", err)
			os.Exit(1)
		}
		cfg, err := config.Initialize(opts.confPath, autoUpdate, reboot, observe)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Configuration initialization failed:", err)
			os.Exit(1)
		}
		path := opts.confPath
		if path == "" {
			path = config.DefaultConfigPath()
		}
		fmt.Printf("Configuration: %s\nObservation mode (no recovery actions): %t\nAutomatic updates: %t\nEmergency reboot: %t\nChecks: %ds healthy / %ds during outage\nMinimum outage before reboot: %ds\n", path, cfg.ObservationMode, cfg.AutoUpdate, cfg.EnableReboot, cfg.CheckIntervalSec, cfg.RecoveryIntervalSec, cfg.RebootMinOutageSec)
		return
	}

	cfg, err := config.Load(opts.confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	svcMgr := service.NewManager(cfg)

	switch cmd {
	case "logs", "log":
		os.Exit(runLogs(cfg.LogFile, opts.commands[1:]))
	case "live":
		os.Exit(runLive(cfg.LogFile))
	case "run":
		w := watchdog.NewWatchdog(cfg, opts.verbose)
		w.SetJSONMode(opts.jsonOutput)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		if err := svcMgr.Run(ctx, w); err != nil {
			fmt.Fprintf(os.Stderr, "Daemon runtime error: %v\n", err)
			os.Exit(1)
		}

	case "check":
		w := watchdog.NewWatchdog(cfg, opts.verbose && !opts.jsonOutput)
		w.SetJSONMode(opts.jsonOutput)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}

		if opts.dryRun {
			report, err := w.EvaluateDryRun(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Dry-run evaluation error: %v\n", err)
				os.Exit(1)
			}
			if opts.jsonOutput {
				data, _ := json.MarshalIndent(report, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Println("=== NETRISER DRY-RUN EVALUATION ===")
				fmt.Printf("Healthy:          %t\n", report.Healthy)
				fmt.Printf("Fail Count:       %d (projected: %d)\n", report.CurrentFailCount, report.ProjectedFailCount)
				fmt.Printf("Escalation Stage: %d\n", report.EscalationStage)
				fmt.Printf("Reason:           %s\n", report.Reason)
				fmt.Println("Planned Actions:")
				for _, act := range report.PlannedActions {
					fmt.Printf("  - %s\n", act)
				}
			}
			if !report.Healthy {
				os.Exit(2)
			}
			os.Exit(0)
		}

		report, err := w.RunCheckCycle(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Check cycle error: %v\n", err)
			os.Exit(1)
		}

		if opts.jsonOutput {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
		} else {
			if report.Healthy {
				if report.Remediated && report.CanaryResult.DNSOnlyFailure() {
					fmt.Println("System DNS restored without reboot.")
				} else if report.Remediated {
					fmt.Printf("Connectivity RESTORED by Stage %d remediation at fail count %d!\n", report.RemediationStage, report.InitialFailCount)
				} else {
					fmt.Println("Connectivity is healthy. All probes responded.")
				}
			} else {
				if report.CanaryResult.DNSOnlyFailure() {
					fmt.Fprintln(os.Stderr, "System DNS resolution failed; IP connectivity is healthy. DNS-only recovery does not trigger reboot.")
				} else {
					fmt.Fprintf(os.Stderr, "Connectivity FAILED at fail count %d (Remediation stage: %d)\n", report.FailCount, report.RemediationStage)
				}
			}
		}

		if !report.Healthy {
			os.Exit(2)
		}

	case "dry-run":
		w := watchdog.NewWatchdog(cfg, opts.verbose && !opts.jsonOutput)
		w.SetJSONMode(opts.jsonOutput)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		report, err := w.EvaluateDryRun(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Dry-run evaluation error: %v\n", err)
			os.Exit(1)
		}
		if opts.jsonOutput {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Println("=== NETRISER DRY-RUN EVALUATION ===")
			fmt.Printf("Healthy:          %t\n", report.Healthy)
			fmt.Printf("Fail Count:       %d (projected: %d)\n", report.CurrentFailCount, report.ProjectedFailCount)
			fmt.Printf("Escalation Stage: %d\n", report.EscalationStage)
			fmt.Printf("Reason:           %s\n", report.Reason)
			fmt.Println("Planned Actions:")
			for _, act := range report.PlannedActions {
				fmt.Printf("  - %s\n", act)
			}
		}
		if !report.Healthy {
			os.Exit(2)
		}

	case "check-config", "config-check":
		w := watchdog.NewWatchdog(cfg, false)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		rep := w.ValidateConfiguration(ctx)
		if opts.jsonOutput {
			data, _ := json.MarshalIndent(rep, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Println("=== CONFIGURATION VALIDATION ===")
			fmt.Printf("Configuration File: %s\n", rep.ConfigFile)
			fmt.Printf("Valid:              %t\n", rep.Valid)
			fmt.Printf("Baseline Interface: %s\n", rep.Baseline.Interface)
			fmt.Printf("Baseline Gateway:   %s\n", rep.Baseline.Gateway)
			fmt.Printf("Log File:           %s\n", cfg.LogFile)
			fmt.Printf("Incident Reports:   %s\n", cfg.IncidentDir)
			if len(rep.Errors) > 0 {
				fmt.Println("\nValidation Errors:")
				for _, e := range rep.Errors {
					fmt.Printf("  [!] %s\n", e)
				}
			}
			if len(rep.Warnings) > 0 {
				fmt.Println("\nValidation Warnings:")
				for _, warn := range rep.Warnings {
					fmt.Printf("  [*] %s\n", warn)
				}
			}
			if rep.Valid && len(rep.Errors) == 0 {
				fmt.Println("\nResult: Configuration is VALID.")
			}
		}
		if !rep.Valid {
			os.Exit(1)
		}

	case "status":
		w := watchdog.NewWatchdog(cfg, opts.verbose && !opts.jsonOutput)
		w.SetJSONMode(opts.jsonOutput)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		if opts.jsonOutput {
			jsonStr, err := w.StatusJSON(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating status JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(jsonStr)
		} else {
			fmt.Print(w.Status(ctx))
		}

	case "diagnose":
		w := watchdog.NewWatchdog(cfg, opts.verbose && !opts.jsonOutput)
		w.SetJSONMode(opts.jsonOutput)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		if opts.jsonOutput {
			jsonStr, err := w.DiagnoseJSON(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating diagnostics JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(jsonStr)
		} else {
			dump, err := w.Diagnose(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating diagnostics: %v\n", err)
				os.Exit(1)
			}
			fmt.Print(dump)
		}

	case "simulate-hijack":
		fmt.Println("======================================================================")
		fmt.Println("       SIMULATING ROUTE HIJACK WITH AUTOMATIC SAFETY ROLLBACK         ")
		fmt.Println("======================================================================")
		fmt.Println("This test injects a dummy rogue default route via 198.51.100.254.")
		fmt.Println("An independent background rollback process is registered for 45s.")
		fmt.Println("")

		w := watchdog.NewWatchdog(cfg, true)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		session, err := w.SimulateHijackSession(ctx, 45*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting hijack simulation: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Rogue route injected! Running watchdog check now...")
		rep, cErr := w.RunCheckCycle(ctx)

		fmt.Println("")
		if cErr != nil {
			fmt.Fprintf(os.Stderr, "Check cycle encountered error: %v\n", cErr)
			fmt.Println("Executing immediate safety rollback...")
			_ = session.Rollback(ctx)
			_ = session.Disarm()
			os.Exit(1)
		}

		if rep != nil && rep.Remediated {
			fmt.Println("SUCCESS: Watchdog detected hijacking and successfully remediated network connectivity!")
			_ = session.Rollback(ctx)
			_ = session.Disarm()
		} else if rep != nil && rep.Healthy {
			fmt.Println("NOTE: Probes remained reachable or route was restored.")
			_ = session.Rollback(ctx)
			_ = session.Disarm()
		} else {
			fmt.Println("WARNING: Connectivity was not restored immediately by Stage 1. Executing rollback...")
			_ = session.Rollback(ctx)
			_ = session.Disarm()
			os.Exit(1)
		}

	case "service":
		subCmd := "status"
		if len(opts.commands) > 1 {
			subCmd = opts.commands[1]
		}
		binPath, _ := os.Executable()
		binPath, _ = filepath.Abs(binPath)
		confPath := opts.confPath
		if confPath != "" {
			confPath, _ = filepath.Abs(confPath)
		}

		switch subCmd {
		case "install":
			if err := svcMgr.Install(binPath, confPath); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to install service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service installed and started successfully.")
		case "uninstall":
			if err := svcMgr.Uninstall(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to uninstall service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service uninstalled successfully.")
		case "start":
			if err := svcMgr.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to start service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service started successfully.")
		case "stop":
			if err := svcMgr.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to stop service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service stopped successfully.")
		case "restart":
			if err := svcMgr.Restart(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to restart service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Service restarted successfully.")
		case "status":
			state, err := svcMgr.Status()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error querying service status: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Service Status: %s\n", state)
		default:
			fmt.Fprintf(os.Stderr, "Unknown service subcommand '%s'. Use install, uninstall, start, stop, restart, or status.\n", subCmd)
			os.Exit(1)
		}

	case "start":
		if err := svcMgr.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service started successfully.")

	case "stop":
		if err := svcMgr.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service stopped successfully.")

	case "restart":
		if err := svcMgr.Restart(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to restart service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Service restarted successfully.")

	case "up":
		_ = svcMgr.Start()
		w := watchdog.NewWatchdog(cfg, opts.verbose)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		_ = w.ApplyPolicy(ctx)
		state, _ := svcMgr.Status()
		fmt.Printf("netriser UP: service is %s, management policy routing enforced.\n", state)

	case "down":
		_ = svcMgr.Stop()
		w := watchdog.NewWatchdog(cfg, opts.verbose)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		_ = w.RemovePolicy(ctx)
		fmt.Println("netriser DOWN: service stopped, management policy routing removed.")

	case "reboot":
		subCmd := "status"
		if len(opts.commands) > 1 {
			subCmd = strings.ToLower(opts.commands[1])
		}

		targetConf := opts.confPath
		if targetConf == "" {
			targetConf = config.DefaultConfigPath()
		}

		switch subCmd {
		case "on", "enable", "1", "true":
			if err := config.SetRebootEnabled(targetConf, true); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to enable reboot: %v\n", err)
				os.Exit(1)
			}
			_ = svcMgr.Restart()
			fmt.Println("======================================================================")
			fmt.Printf("[OK] Emergency Reboot is now ENABLED in %s\n", targetConf)
			fmt.Println("Background service restarted to apply configuration change.")
			fmt.Println("======================================================================")

		case "off", "disable", "0", "false":
			if err := config.SetRebootEnabled(targetConf, false); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to disable reboot: %v\n", err)
				os.Exit(1)
			}
			_ = svcMgr.Restart()
			fmt.Println("======================================================================")
			fmt.Printf("[OK] Emergency Reboot is now DISABLED in %s\n", targetConf)
			fmt.Println("Background service restarted to apply configuration change.")
			fmt.Println("======================================================================")

		case "status":
			loadedCfg, err := config.Load(targetConf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("======================================================================")
			fmt.Printf("Configuration File: %s\n", targetConf)
			if loadedCfg.EnableReboot {
				fmt.Println("Emergency Reboot:   ENABLED (enable_reboot: true)")
			} else {
				fmt.Println("Emergency Reboot:   DISABLED (enable_reboot: false)")
			}
			fmt.Printf("Reboot Grace:       %d seconds\n", loadedCfg.RebootGraceSec)
			fmt.Printf("Reboot Budget:      %d per %d seconds window\n", loadedCfg.RebootBudgetCount, loadedCfg.RebootBudgetWindowSec)
			fmt.Printf("Startup Grace:      %d seconds\n", loadedCfg.StartupGraceSec)
			fmt.Println("======================================================================")
			fmt.Println("To toggle:")
			fmt.Println("  netriser reboot on     (enable emergency reboot)")
			fmt.Println("  netriser reboot off    (disable emergency reboot)")

		default:
			fmt.Fprintf(os.Stderr, "Unknown reboot subcommand '%s'. Use 'on', 'off', or 'status'.\n", subCmd)
			os.Exit(1)
		}

	case "observe", "observation":
		sub := "status"
		if len(opts.commands) > 1 {
			sub = strings.ToLower(opts.commands[1])
		}
		targetConf := opts.confPath
		if targetConf == "" {
			targetConf = config.DefaultConfigPath()
		}
		enabled := cfg.ObservationMode
		switch sub {
		case "on", "enable", "1", "true":
			enabled = true
		case "off", "disable", "0", "false":
			enabled = false
		case "status":
		default:
			fmt.Fprintln(os.Stderr, "Usage: netriser observe [on|off|status]")
			os.Exit(1)
		}
		if sub != "status" {
			if err := config.SetObservationMode(targetConf, enabled); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to change observation mode: %v\n", err)
				os.Exit(1)
			}
			if err := svcMgr.Restart(); err != nil {
				fmt.Fprintf(os.Stderr, "Configuration saved, but the service restart failed: %v\n", err)
			}
		}
		if enabled {
			fmt.Printf("Observation mode: ON (%s). NetRiser logs incidents and changes no routes, services, DNS or updates.\n", targetConf)
			fmt.Println("Enable recovery: netriser observe off")
		} else {
			fmt.Printf("Observation mode: OFF (%s). Recovery actions follow the allow_* settings.\n", targetConf)
			fmt.Println("Log only: netriser observe on")
		}

	case "autoupdate":
		sub := "status"
		if len(opts.commands) > 1 {
			sub = opts.commands[1]
		}
		enabled := cfg.AutoUpdate
		switch sub {
		case "on", "enable":
			enabled = true
		case "off", "disable":
			enabled = false
		case "status":
		default:
			fmt.Fprintln(os.Stderr, "Usage: netriser autoupdate [on|off|status]")
			os.Exit(1)
		}
		if sub != "status" {
			if err := config.SetAutoUpdateEnabled(opts.confPath, enabled); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if opts.jsonOutput {
			data, _ := json.Marshal(map[string]any{"auto_update": enabled, "interval_sec": cfg.AutoUpdateIntervalSec, "update_url": cfg.UpdateURL})
			fmt.Println(string(data))
		} else {
			fmt.Printf("Automatic updates: %t (interval: %ds). Running daemon reloads this setting within 30 seconds.\n", enabled, cfg.AutoUpdateIntervalSec)
		}

	case "update":
		if !opts.checkOnly {
			if err := cfg.EnsureDirectories(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			lock, err := watchdog.AcquireLock(filepath.Join(cfg.StateDir, "update.lock"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Update already running or lock unavailable: %v\n", err)
				os.Exit(1)
			}
			defer lock.Unlock()
		}
		baseURL := cfg.UpdateURL
		if opts.updateURL != "" {
			baseURL = opts.updateURL
		}
		if baseURL == "" {
			baseURL = "https://netriser.repentandliveholy.org"
		}

		up := updater.New(baseURL)
		if err := up.SetTrustedKeys(cfg.UpdatePublicKeys); err != nil {
			fmt.Fprintf(os.Stderr, "Update keys: %v\n", err)
			os.Exit(1)
		}
		info, err := up.Check(ctx, Version, Commit)
		if err != nil {
			if opts.jsonOutput {
				fmt.Printf(`{"status":"error","error":%q}`+"\n", err.Error())
			} else {
				fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
			}
			os.Exit(1)
		}

		if opts.checkOnly {
			if opts.jsonOutput {
				data, _ := json.MarshalIndent(info, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("Current version: %s (commit: %s)\n", info.CurrentVersion, info.CurrentCommit)
				fmt.Printf("Latest version:  %s (commit: %s, signature verified)\n", info.LatestVersion, info.LatestCommit)
				if info.Downgrade {
					fmt.Println("Status: The published release is older than this build; downgrades are never installed.")
				} else if info.UpdateAvailable {
					fmt.Println("Status: Update is AVAILABLE! Run 'netriser update' to install.")
				} else {
					fmt.Println("Status: Already running the latest version.")
				}
			}
			os.Exit(0)
		}

		if info.Downgrade {
			fmt.Fprintf(os.Stderr, "Refusing to downgrade from %s to %s.\n", info.CurrentVersion, info.LatestVersion)
			os.Exit(1)
		}
		if !info.UpdateAvailable && !opts.force {
			if opts.jsonOutput {
				data, _ := json.MarshalIndent(map[string]any{
					"status":  "already_up_to_date",
					"version": info.CurrentVersion,
					"commit":  info.CurrentCommit,
				}, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("netriser is already up to date (version: %s, commit: %s).\nUse 'netriser update --force' to reinstall.\n", info.CurrentVersion, info.CurrentCommit)
			}
			os.Exit(0)
		}

		if !opts.jsonOutput {
			fmt.Printf("Updating netriser: %s -> %s (commit: %s)...\n", info.CurrentVersion, info.LatestVersion, info.LatestCommit)
			fmt.Printf("Downloading binary from %s...\n", info.DownloadURL)
		}

		if err := up.Apply(ctx, "", info); err != nil {
			if opts.jsonOutput {
				fmt.Printf(`{"status":"error","error":%q}`+"\n", err.Error())
			} else {
				fmt.Fprintf(os.Stderr, "Failed to apply update: %v\n", err)
			}
			os.Exit(1)
		}

		// Attempt to restart background service if installed and running
		// (launchctl load reports success even when the plist is missing, so
		// the service state is checked first.)
		restarted := false
		if state, err := svcMgr.Status(); err == nil && serviceRunning(state) {
			restarted = svcMgr.Restart() == nil
		}

		if opts.jsonOutput {
			data, _ := json.MarshalIndent(map[string]any{
				"status":            "updated",
				"previous_version":  info.CurrentVersion,
				"new_version":       info.LatestVersion,
				"commit":            info.LatestCommit,
				"service_restarted": restarted,
			}, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Successfully updated to netriser v%s (commit: %s)!\n", info.LatestVersion, info.LatestCommit)
			if restarted {
				fmt.Println("Background service has been restarted automatically.")
			} else {
				fmt.Println("Note: If running as a background service, restart it to apply changes.")
			}
		}

	case "apply-policy":
		w := watchdog.NewWatchdog(cfg, true)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		if err := w.ApplyPolicy(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to apply policy routing: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Management policy routing enforced successfully.")

	case "remove-policy":
		w := watchdog.NewWatchdog(cfg, true)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		if err := w.RemovePolicy(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove policy routing: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Management policy routing removed.")

	case "reset":
		w := watchdog.NewWatchdog(cfg, true)
		if opts.confPath != "" {
			w.SetConfigPath(opts.confPath)
		}
		w.Reset()
		fmt.Println("Watchdog failure count reset to 0.")

	case "version":
		if opts.jsonOutput {
			fmt.Printf(`{"version":%q,"commit":%q,"build_time":%q}`+"\n", Version, Commit, BuildTime)
		} else {
			fmt.Printf("netriser version %s (commit: %s, built at: %s)\n", Version, Commit, BuildTime)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown command '%s'. Run 'netriser --help' for usage.\n", cmd)
		os.Exit(1)
	}
}

func optionalBool(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	v, err := strconv.ParseBool(value)
	return &v, err
}
