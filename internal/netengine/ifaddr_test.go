package netengine

import (
	"net"
	"strings"
	"testing"
)

func TestFirstIPv4LineSkipsStderrNoise(t *testing.T) {
	out := "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><Obj S=\"progress\">Preparing modules for first use.</Obj></Objs>\r\n192.168.1.135\r\n"
	if got := firstIPv4Line(out); got != "192.168.1.135" {
		t.Fatalf("firstIPv4Line = %q", got)
	}
	for _, bad := range []string{"", "WARNING: something", "fe80::1", "not an ip"} {
		if got := firstIPv4Line(bad); got != "" {
			t.Fatalf("firstIPv4Line(%q) = %q, want empty", bad, got)
		}
	}
}

func TestFirstUsableIPv4SkipsLinkLocalAndIPv6(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("169.254.10.2").To4(), Mask: net.CIDRMask(16, 32)},
		&net.IPNet{IP: net.ParseIP("192.168.1.135").To4(), Mask: net.CIDRMask(24, 32)},
	}
	if got := firstUsableIPv4(addrs); got != "192.168.1.135" {
		t.Fatalf("firstUsableIPv4 = %q", got)
	}
	if got := firstUsableIPv4(addrs[:2]); got != "" {
		t.Fatalf("only link-local/IPv6 gave %q", got)
	}
}

func TestInterfaceIPv4UnknownInterface(t *testing.T) {
	if got := interfaceIPv4("no-such-interface-netriser"); got != "" {
		t.Fatalf("interfaceIPv4 = %q", got)
	}
}

func TestCommandDetail(t *testing.T) {
	if commandDetail("  \r\n ") != "" {
		t.Fatal("empty output must give no detail")
	}
	got := commandDetail("Restart-NetAdapter : Element not found.\r\n  At line:9")
	if got != ": Restart-NetAdapter : Element not found. At line:9" {
		t.Fatalf("commandDetail = %q", got)
	}
	if long := commandDetail(strings.Repeat("x", 500)); len(long) != 2+300+3 {
		t.Fatalf("long output not shortened: %d", len(long))
	}
}
