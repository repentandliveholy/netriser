package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/i18n"
	"github.com/repentandliveholy/netriser/internal/service"
	"github.com/repentandliveholy/netriser/internal/setup"
	"github.com/repentandliveholy/netriser/internal/term"
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
		"full_tunnel":      opts.installFullTunnel,
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

	// --lang selects the language of the questions and the result. It is
	// stored only when it differs from the configured language, so that
	// installers passing --lang leave existing files otherwise untouched.
	switch opts.lang {
	case "":
	case "en", "ru", "fr":
		if cur, _, err := setup.Current(path); err == nil && setup.EffectiveLanguage(cur) != opts.lang {
			explicit["language"] = opts.lang
		}
	default:
		fmt.Fprintln(os.Stderr, "Invalid --lang: use en, ru or fr.")
		return 1
	}

	// Fail before the questions, not after them: applying the answers needs
	// write access to the configuration (administrator rights by default).
	if opts.saveAnswers == "" {
		if err := configWritable(path); err != nil {
			lang := opts.lang
			if lang == "" {
				lang = i18n.FromEnvironment()
			}
			key := "need_root"
			if runtime.GOOS == "windows" {
				key = "need_admin"
			}
			if !errors.Is(err, fs.ErrPermission) {
				// Not a rights problem (read-only disk, missing drive): show it.
				fmt.Fprintln(os.Stderr, "Configuration cannot be saved:", err)
				return 1
			}
			fmt.Fprintln(os.Stderr, i18n.T(lang, key, path))
			return 1
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
		setupOpts := setup.Options{ConfigPath: path, Explicit: explicit, Language: opts.lang}
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
	lang := opts.lang
	if lang == "" {
		lang = cfg.Language
	}
	t := func(key string, args ...any) string { return i18n.T(lang, key, args...) }
	yesNo := func(v bool) string {
		if v {
			return t("yes")
		}
		return t("no")
	}
	style := term.For(os.Stdout)
	state := t("res_unchanged")
	if changed {
		state = t("res_updated")
	}
	fmt.Println(style.Bold(t("res_config", path, state)))
	fmt.Println(t("res_observation", yesNo(cfg.ObservationMode)))
	fmt.Println(t("res_autoupdate", yesNo(cfg.AutoUpdate)))
	fmt.Println(t("res_reboot", yesNo(cfg.EnableReboot)))
	fmt.Println(t("res_route", routePolicyText(lang, cfg)))
	if len(cfg.AllowedDefaultInterfaces) > 0 {
		fmt.Println(t("res_allowed", strings.Join(cfg.AllowedDefaultInterfaces, ", ")))
	}
	fmt.Println(t("res_checks", cfg.CheckIntervalSec, cfg.RecoveryIntervalSec))
	fmt.Println(t("res_log", cfg.LogFile))
	fmt.Println(t("res_incidents", cfg.IncidentDir))
	if changed && !opts.noRestart {
		mgr := service.NewManager(cfg)
		if state, err := mgr.Status(); err == nil && serviceRunning(state) {
			if err := mgr.Restart(); err != nil {
				fmt.Fprintln(os.Stderr, t("res_restart_fail", err))
				return 1
			}
			fmt.Println(style.Green(t("res_restarted")))
		}
	}
	return 0
}

// configWritable checks, without changing anything, that the configuration
// file can be written: the file itself when it exists, otherwise its nearest
// existing parent directory.
func configWritable(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	tmp, err := os.CreateTemp(dir, ".netriser-access-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_ = tmp.Close()
	return os.Remove(name)
}

func serviceRunning(state string) bool {
	s := strings.ToLower(state)
	return (strings.Contains(s, "active") && !strings.Contains(s, "inactive")) || strings.Contains(s, "running")
}

// routePolicyText is config.DefaultRoutePolicy in the setup language.
func routePolicyText(lang string, cfg *config.Config) string {
	switch {
	case cfg.UplinkOnly():
		return i18n.T(lang, "policy_uplink")
	case cfg.FullTunnel == nil:
		v := i18n.T(lang, "no")
		if cfg.AllowVPNBypass {
			v = i18n.T(lang, "yes")
		}
		return i18n.T(lang, "policy_unset", v)
	case cfg.AllowVPNBypass:
		return i18n.T(lang, "policy_access")
	default:
		return i18n.T(lang, "policy_privacy")
	}
}
