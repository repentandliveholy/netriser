package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
	"github.com/repentandliveholy/netriser/internal/setup"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

// runBlockers implements `netriser blockers [scan|disable|restore]`.
func runBlockers(ctx context.Context, cfg *config.Config, opts cliOptions) int {
	sub := "scan"
	if len(opts.commands) > 1 {
		sub = strings.ToLower(opts.commands[1])
	}
	w := watchdog.NewWatchdog(cfg, opts.verbose && !opts.jsonOutput)
	w.SetJSONMode(opts.jsonOutput)
	if opts.confPath != "" {
		w.SetConfigPath(opts.confPath)
	}

	switch sub {
	case "scan", "status", "list":
		scan, err := w.ScanBlockers(ctx)
		if opts.jsonOutput {
			data, _ := json.MarshalIndent(scan, "", "  ")
			fmt.Println(string(data))
		} else {
			printBlockerScan(scan)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Examining services and drivers failed:", err)
			return 1
		}
		return 0

	case "disable":
		if err := cfg.EnsureDirectories(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		lock, err := acquireLockRetry(cfg.LockFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "NetRiser is busy (a check is running); try again in a minute:", err)
			return 1
		}
		defer lock.Unlock()
		scan, err := w.ScanBlockers(ctx)
		printBlockerScan(scan)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Examining services and drivers failed:", err)
			return 1
		}
		if len(scan.Candidates) == 0 {
			return 0
		}
		if !opts.yes {
			ok, asked := confirm("Disable these now? They are kept on disk; undo: nr blockers restore all [Y/n] ")
			if !asked {
				fmt.Fprintln(os.Stderr, "No terminal to confirm; run again with --yes.")
				return 1
			}
			if !ok {
				fmt.Println("Nothing changed.")
				return 0
			}
		}
		for _, a := range w.DisableBlockers(ctx, scan.Candidates) {
			fmt.Println("  " + a.String())
		}
		time.Sleep(3 * time.Second)
		after, _ := w.ScanBlockers(ctx)
		switch {
		case after == nil || !after.Access.Tested():
			fmt.Println("Restart Windows to make sure the disabled components are unloaded: shutdown /r /t 0")
		case after.Access.Blocked():
			fmt.Printf("This host still cannot connect to its own ports (%s). The disabled drivers stay loaded until Windows restarts: shutdown /r /t 0\n", after.Access.Summary())
		default:
			fmt.Printf("Local access works again (%s).\n", after.Access.Summary())
		}
		return 0

	case "restore", "enable", "undo":
		names := opts.commands[2:]
		if len(names) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: netriser blockers restore <name ...|all>")
			return 1
		}
		if len(names) == 1 && strings.EqualFold(names[0], "all") {
			names = nil
		}
		if err := cfg.EnsureDirectories(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		lock, err := acquireLockRetry(cfg.LockFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "NetRiser is busy (a check is running); try again in a minute:", err)
			return 1
		}
		defer lock.Unlock()
		actions, err := w.RestoreBlockers(ctx, names)
		for _, a := range actions {
			fmt.Println("  " + a.String())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(actions) == 0 {
			fmt.Println("Nothing was disabled by NetRiser.")
			return 0
		}
		fmt.Println("They start again when Windows restarts (or with: sc start <name>). If one of them blocked this host, NetRiser disables it again; to keep it, add it to protected_components.")
		return 0
	}
	fmt.Fprintln(os.Stderr, "Usage: netriser blockers [scan|disable [--yes]|restore <name ...|all>]")
	return 1
}

func printBlockerScan(scan *watchdog.BlockerScan) {
	if scan == nil {
		return
	}
	if !scan.Supported {
		fmt.Println("Local block recovery is available on Windows only.")
		return
	}
	switch {
	case !scan.Access.Tested():
		fmt.Println("Local access:  not tested (none of access_ports listens on this host's address)")
	case scan.Access.Blocked():
		fmt.Printf("Local access:  BLOCKED on %s (%s): something on this host blocks connections\n", scan.Access.Address, scan.Access.Summary())
	default:
		fmt.Printf("Local access:  ok on %s (%s)\n", scan.Access.Address, scan.Access.Summary())
	}
	if scan.Snapshot.IsZero() {
		fmt.Println("Snapshot:      none yet (taken while the host works); only drivers without a trusted signature are considered")
	} else {
		fmt.Printf("Snapshot:      working state from %s\n", scan.Snapshot.Local().Format("2006-01-02 15:04"))
	}
	if !scan.Enabled {
		fmt.Println("Recovery:      off (local_block_recovery: false); NetRiser only reports")
	}
	if len(scan.Candidates) == 0 {
		fmt.Println("Would disable: nothing")
	} else {
		fmt.Println("Would disable:")
		for _, b := range scan.Candidates {
			kind := "service"
			if b.Kernel {
				kind = "driver"
			}
			signer := b.Sig.Signer
			if signer == "" {
				signer = "unsigned"
			}
			if !b.Sig.Valid && b.Sig.Status != "" {
				signer += ", " + b.Sig.Status
			}
			fmt.Printf("  %-22s %-7s %-9s %s\n", b.Name, kind, netengine.StartName(b.Start), b.Reason)
			fmt.Printf("  %-22s signer: %s\n", "", signer)
			if b.Image != "" {
				fmt.Printf("  %-22s image:  %s\n", "", b.Image)
			}
		}
	}
	if len(scan.Disabled) > 0 {
		fmt.Println("Disabled by NetRiser (undo: nr blockers restore all):")
		for _, d := range scan.Disabled {
			fmt.Printf("  %-22s was %-9s since %s  %s\n", d.Name, netengine.StartName(d.PreviousStart), d.DisabledAt.Local().Format("2006-01-02 15:04"), d.Reason)
		}
	}
}

// confirm asks a yes/no question on the terminal; Enter means yes. asked is
// false when there is no terminal.
func confirm(question string) (ok, asked bool) {
	in, out, closeTerminal, has := setup.Terminal()
	defer closeTerminal()
	if !has {
		return false, false
	}
	fmt.Fprint(out, question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, true
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, true
	}
	return false, true
}

func acquireLockRetry(path string) (watchdog.FileLock, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		lock, err := watchdog.AcquireLock(path)
		if err == nil {
			return lock, nil
		}
		lastErr = err
		if !errors.Is(err, watchdog.ErrAlreadyRunning) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	return nil, lastErr
}
