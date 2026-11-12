package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/repentandliveholy/netriser/internal/canary"
	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
)

func stubOpts(path, input string, probeOK bool) (Options, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return Options{
		ConfigPath: path, Interactive: true, In: strings.NewReader(input), Out: out, GOOS: "linux",
		Probe: func(_ context.Context, cfg *config.Config) canary.HealthResult {
			var res canary.HealthResult
			for _, t := range cfg.CanaryTargets {
				res.Details = append(res.Details, canary.TargetResult{Target: t, Group: canary.GroupInternet, Success: probeOK})
			}
			return res
		},
		Detect: func() []Detected {
			return []Detected{{"wg0", "WireGuard", netengine.KindVPN}, {"tailscale0", "Tailscale", netengine.KindMesh}}
		},
		Uplink: func(context.Context, *config.Config) string { return "eth0 (gateway 192.0.2.1)" },
	}, out
}

func TestFreshSetupDefaultsAreSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// Enter for every question accepts the defaults.
	opts, out := stubOpts(path, strings.Repeat("\n", 40), true)
	values, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg, _, err := config.Apply(path, values)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ObservationMode || cfg.AllowVPNBypass || cfg.EnableReboot || !cfg.AutoUpdate || len(cfg.AllowedDefaultInterfaces) != 0 || !cfg.UplinkOnly() {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
	text := out.String()
	for _, want := range []string{"netriser setup", "wg0", "WireGuard (vpn)", "tailscale0", "Detected physical uplink: eth0", "Summary"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
}

func TestSetupAnswersAreApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := strings.Join([]string{
		"n",                            // observation mode
		"n",                            // use these probes
		"192.0.2.53:53, 192.0.2.54:53", // custom probes
		"y",                            // use these probes (re-tested)
		"10.0.0.1:22",                  // mesh canaries
		"y",                            // all traffic through VPN
		"",                             // accept suggested wg0
		"y",                            // access over keeping traffic in the VPN
		"y",                            // add custom overlay
		"corp",                         // name
		"^corp[0-9]+$",                 // pattern
		"n",                            // full-tunnel VPN
		"corp-vpn.service",             // services
		"n",                            // add another
		"", "", "", "",                 // stages 1-3, dns
		"eth1",     // uplink
		"y", "600", // reboot, outage
		"n", // auto update
		"y", // save
	}, "\n") + "\n"
	opts, out := stubOpts(path, input, true)
	values, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg, changed, err := config.Apply(path, values)
	if err != nil || !changed {
		t.Fatalf("apply: %v", err)
	}
	if cfg.ObservationMode || cfg.CanaryTargets[1] != "192.0.2.54:53" || cfg.MeshCanaries[0] != "10.0.0.1:22" ||
		cfg.AllowedDefaultInterfaces[0] != "wg0" || !cfg.AllowVPNBypass || cfg.FullTunnel == nil || !*cfg.FullTunnel || cfg.Overlays[0].Services[0] != "corp-vpn.service" ||
		cfg.ManagementInterface != "eth1" || !cfg.EnableReboot || cfg.RebootMinOutageSec != 600 || cfg.AutoUpdate {
		t.Fatalf("answers not applied: %+v\n%s", cfg, out)
	}

	// Rerun: Enter keeps every current answer and changes nothing.
	before, _ := os.ReadFile(path)
	opts, out = stubOpts(path, strings.Repeat("\n", 40), true)
	values, err = Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, changed, err := config.Apply(path, values); err != nil || changed {
		t.Fatalf("rerun with Enter changed settings: %v %v\n%s", changed, err, out)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || !strings.Contains(out.String(), "No changes") {
		t.Fatalf("rerun modified configuration:\n%s", out)
	}
}

func TestSetupWarnsWhenProbesFailAndRequiresTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// observation, reject probes, clear list (refused), reject again, enter a
	// target that also fails, accept it anyway, then defaults.
	input := "\n" + "\n" + "-\n" + "\n" + "192.0.2.1:53\n" + "y\n" + strings.Repeat("\n", 40)
	opts, out := stubOpts(path, input, false)
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "probes answered") || !strings.Contains(text, "At least one internet probe is required") {
		t.Fatalf("missing probe guidance:\n%s", text)
	}
}

func TestSetupCancelAndEndOfInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// 12 questions without detected overlays (no full tunnel, so no bypass
	// question), then decline saving.
	opts, _ := stubOpts(path, strings.Repeat("\n", 12)+"n\n", true)
	opts.Detect = func() []Detected { return nil }
	if _, err := Run(context.Background(), opts); !errors.Is(err, ErrCancelled) {
		t.Fatalf("declined save: %v", err)
	}
	opts, _ = stubOpts(path, "y\n", true)
	if _, err := Run(context.Background(), opts); !errors.Is(err, ErrCancelled) {
		t.Fatalf("end of input: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("configuration written")
	}
}

func TestExplicitSettingsSkipQuestionsAndNonInteractive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	values, err := Run(context.Background(), Options{ConfigPath: path, Explicit: map[string]any{"observation_mode": false}})
	if err != nil || len(values) != 1 || values["observation_mode"] != false {
		t.Fatalf("non-interactive: %v %v", values, err)
	}
	opts, out := stubOpts(path, strings.Repeat("\n", 40), true)
	opts.Explicit = map[string]any{"observation_mode": false, "enable_reboot": true}
	values, err = Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "observation (read-only) mode [") || values["enable_reboot"] != true {
		t.Fatalf("explicit setting was asked:\n%s", out)
	}
}

// Answering "no full tunnel" records full_tunnel: false, clears interfaces
// allowed to carry the default route and does not ask about VPN bypass.
func TestSetupWithoutFullTunnelSkipsBypassQuestion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("allowed_default_interfaces: [wg0]\nallow_vpn_bypass: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input := "\n\n\n" + "n\n" + strings.Repeat("\n", 40) // observation, probes, mesh, full tunnel = no
	opts, out := stubOpts(path, input, true)
	values, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg, _, err := config.Apply(path, values)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UplinkOnly() || len(cfg.AllowedDefaultInterfaces) != 0 {
		t.Fatalf("no-full-tunnel answer not applied: %+v", cfg)
	}
	text := out.String()
	if strings.Contains(text, "more important than keeping all traffic") || !strings.Contains(text, "removed immediately, even while") {
		t.Fatalf("wrong questions for a host without a full tunnel:\n%s", text)
	}
}
