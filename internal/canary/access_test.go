package canary

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/repentandliveholy/netriser/internal/config"
)

func TestPingCommand(t *testing.T) {
	cases := map[string]string{
		"linux|100.64.0.1":     "ping -c 1 -W 2 100.64.0.1",
		"darwin|100.64.0.1":    "ping -c 1 -t 2 100.64.0.1",
		"darwin|fd7a::1":       "ping6 -c 1 fd7a::1",
		"windows|100.64.0.1":   "ping -n 1 -w 2000 100.64.0.1",
		"windows|fd7a:115c::1": "ping -n 1 -w 2000 -6 fd7a:115c::1",
	}
	for in, want := range cases {
		goos, host, _ := strings.Cut(in, "|")
		if got := strings.Join(pingCommand(goos, host, 2*time.Second), " "); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func TestPingAnsweredRequiresWindowsReply(t *testing.T) {
	unreachable := "Reply from 192.168.1.1: Destination host unreachable."
	if pingAnswered("windows", "100.64.0.1", unreachable, nil) {
		t.Error("router 'unreachable' reply counted as an answer")
	}
	if !pingAnswered("windows", "100.64.0.1", "Reply from 100.64.0.1: bytes=32 time=12ms TTL=64", nil) {
		t.Error("real reply not counted")
	}
	if pingAnswered("linux", "100.64.0.1", "", errors.New("exit status 1")) {
		t.Error("failed ping counted")
	}
}

func accessChecker(targets ...string) *Checker {
	cfg := config.DefaultConfig()
	cfg.DNSCanaries = nil
	cfg.ProbeTimeoutSec = 2
	cfg.MeshCanaries = targets
	return NewChecker(cfg)
}

// A closed port that refuses the connection proves the host is reachable.
func TestAccessProbeCountsRefusedConnection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // now refused
	res := accessChecker(addr).probeSingle(context.Background(), addr, GroupMesh)
	if !res.Success || res.Protocol != ProtoTCP {
		t.Fatalf("refused connection not counted as an answer: %+v", res)
	}
	unroutable := "198.51.100.254:22"
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if res := accessChecker(unroutable).probeSingle(ctx, unroutable, GroupMesh); res.Success {
		t.Fatalf("unreachable address answered: %+v", res)
	}
}

func TestAccessProbeWithoutPortPings(t *testing.T) {
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("no ping command")
	}
	res := accessChecker("127.0.0.1").probeSingle(context.Background(), "127.0.0.1", GroupMesh)
	if res.Protocol != ProtoPing || !res.Success {
		t.Fatalf("ping of loopback failed: %+v", res)
	}
}

// Reaching the internet quorum must not cancel the access probes; otherwise
// access looks lost whenever the internet answers quickly.
func TestFastCheckWaitsForAccessProbes(t *testing.T) {
	internet, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer internet.Close()
	go func() {
		for {
			c, err := internet.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	// A ping takes far longer than a local TCP connect, so the internet
	// quorum is reached while the access probe is still running.
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("no ping command")
	}
	cfg := config.DefaultConfig()
	cfg.DNSCanaries = nil
	cfg.ProbeTimeoutSec = 2
	cfg.HTTPFallbackURL = ""
	cfg.CanaryTargets = []string{internet.Addr().String()}
	cfg.MinHealthyTargets = 1
	cfg.MeshCanaries = []string{"127.0.0.1"}
	res := NewChecker(cfg).CheckFast(context.Background())
	if !res.InternetHealthy || !res.MeshHealthy || res.AccessLost() {
		t.Fatalf("access probe cancelled by the internet quorum: %+v", res)
	}

	cfg.MeshCanaries = []string{"198.51.100.254:22"}
	res = NewChecker(cfg).CheckFast(context.Background())
	if !res.AccessLost() {
		t.Fatalf("lost access not reported: %+v", res)
	}
}
