package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/service"
	"github.com/repentandliveholy/netriser/internal/setup"
)

// runSetup implements `netriser setup`. Installers run it twice: first with
// --save-answers before changing anything, then with --answers once the
// binary is installed, so the service is not stopped while questions wait.
func runSetup(opts cliOptions) int {
	path := opts.confPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	explicit := map[string]any{}
	for key, raw := range map[string]string{
		"observation_mode": opts.installObserve,
		"auto_update":      opts.installAutoUpdate,
		"enable_reboot":    opts.installReboot,
		"allow_vpn_bypass": opts.installVPNBypass,
	} {
		v, err := optionalBool(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid setting for %s: use true or false.\n", key)
			return 1
		}
		if v != nil {
			explicit[key] = *v
		}
	}

	var values map[string]any
	if opts.answers != "" {
		data, err := os.ReadFile(opts.answers)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Read answers:", err)
			return 1
		}
		if err := yaml.Unmarshal(data, &values); err != nil {
			fmt.Fprintln(os.Stderr, "Parse answers:", err)
			return 1
		}
		if values == nil {
			values = map[string]any{}
		}
		for k, v := range explicit {
			values[k] = v
		}
	} else {
		interactive := !opts.nonInteractive && os.Getenv("NETRISER_NONINTERACTIVE") != "1"
		setupOpts := setup.Options{ConfigPath: path, Explicit: explicit}
		if interactive {
			in, out, closeTerminal, ok := setup.Terminal()
			defer closeTerminal()
			if ok {
				setupOpts.Interactive, setupOpts.In, setupOpts.Out = true, in, out
			} else {
				fmt.Fprintln(os.Stderr, "No terminal available; applying only explicit settings (see 'netriser setup --help').")
			}
		}
		var err error
		values, err = setup.Run(context.Background(), setupOpts)
		if errors.Is(err, setup.ErrCancelled) {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Setup failed:", err)
			return 1
		}
	}

	if opts.saveAnswers != "" {
		data, err := yaml.Marshal(values)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := os.WriteFile(opts.saveAnswers, data, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "Save answers:", err)
			return 1
		}
		return 0
	}

	cfg, changed, err := config.Apply(path, values)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Configuration was not changed:", err)
		return 1
	}
	fmt.Printf("Configuration: %s (%s)\n", path, map[bool]string{true: "updated", false: "unchanged"}[changed])
	fmt.Printf("Observation mode (no recovery actions): %t\nAutomatic updates: %t\nEmergency reboot: %t\nBypass full-tunnel VPNs: %t\n", cfg.ObservationMode, cfg.AutoUpdate, cfg.EnableReboot, cfg.AllowVPNBypass)
	if len(cfg.AllowedDefaultInterfaces) > 0 {
		fmt.Printf("Interfaces allowed to carry the default route: %s\n", strings.Join(cfg.AllowedDefaultInterfaces, ", "))
	}
	fmt.Printf("Checks: %ds healthy / %ds during outage\n", cfg.CheckIntervalSec, cfg.RecoveryIntervalSec)
	if changed && !opts.noRestart {
		mgr := service.NewManager(cfg)
		if state, err := mgr.Status(); err == nil && serviceRunning(state) {
			if err := mgr.Restart(); err != nil {
				fmt.Fprintf(os.Stderr, "Settings saved, but the service restart failed: %v\n", err)
				return 1
			}
			fmt.Println("Service restarted to apply the new settings.")
		}
	}
	return 0
}

func serviceRunning(state string) bool {
	s := strings.ToLower(state)
	return (strings.Contains(s, "active") && !strings.Contains(s, "inactive")) || strings.Contains(s, "running")
}
