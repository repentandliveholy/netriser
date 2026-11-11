package netengine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resolverFixture(t *testing.T) (*LinuxEngine, *linuxRunner, string, []byte) {
	t.Helper()
	e, r, _ := linuxFixture(t)
	path := filepath.Join(t.TempDir(), "resolv.conf")
	good := []byte("nameserver 10.0.0.53\nsearch internal.example\noptions timeout:2\n")
	if err := os.WriteFile(path, good, 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	e.resolvConfPath = path
	return e, r, path, good
}

func TestDNSRestoreUsesHealthyPrivateResolverAndPreservesSymlink(t *testing.T) {
	e, r, path, good := resolverFixture(t)
	link := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	e.resolvConfPath = link
	if err := e.CaptureDNSBaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	bad := []byte("nameserver 192.0.2.1\n")
	if err := os.WriteFile(path, bad, 0644); err != nil {
		t.Fatal(err)
	}
	acts, err := e.RestoreDNS(context.Background())
	if err != nil || acts[0].Status != ActionExecuted {
		t.Fatalf("restore: %+v %v", acts, err)
	}
	got, _ := os.ReadFile(link)
	if string(got) != string(good) {
		t.Fatalf("private DNS/search/options not restored: %s", got)
	}
	if _, err := os.Readlink(link); err != nil {
		t.Fatal("resolver symlink replaced", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("static DNS repair changed services: %v", r.calls)
	}
	failed, _ := os.ReadFile(filepath.Join(e.cfg.StateDir, "dns-resolv.failed"))
	if string(failed) != string(bad) {
		t.Fatal("failed config not preserved")
	}
}

func TestDNSRefusesUntrustedBaselineAndChangedTarget(t *testing.T) {
	e, _, path, _ := resolverFixture(t)
	if _, err := e.RestoreDNS(context.Background()); err == nil {
		t.Fatal("repaired without trusted baseline")
	}
	if err := e.CaptureDNSBaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("keep me"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RestoreDNS(context.Background()); err == nil {
		t.Fatal("overwrote changed target")
	}
	got, _ := os.ReadFile(other)
	if string(got) != "keep me" {
		t.Fatal("unrelated target modified")
	}
}

func TestDNSManagedResolverRestartFailureReported(t *testing.T) {
	e, r, _, _ := resolverFixture(t)
	b := dnsBaseline{Path: e.resolverPath(), Target: "/run/systemd/resolve/stub-resolv.conf", Content: []byte("nameserver 127.0.0.53\n"), ManagedResolved: true}
	data, _ := json.Marshal(b)
	if err := os.WriteFile(filepath.Join(e.cfg.StateDir, "dns-baseline.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	r.failures["systemctl restart systemd-resolved"] = os.ErrPermission
	acts, err := e.RestoreDNS(context.Background())
	if err == nil || acts[0].Status != ActionFailed || !strings.Contains(acts[0].Error, "permission") {
		t.Fatalf("hidden restart error: %+v %v", acts, err)
	}
}

func TestDNSDoesNotCacheRecentlyChangedResolver(t *testing.T) {
	e, _, path, _ := resolverFixture(t)
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		t.Fatal(err)
	}
	if err := e.CaptureDNSBaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, "dns-baseline.json")); !os.IsNotExist(err) {
		t.Fatal("recent file cached before resolver refresh")
	}
}
