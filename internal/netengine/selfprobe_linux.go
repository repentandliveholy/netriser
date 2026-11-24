//go:build linux

package netengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// The temporary veth pair of the self-probe (see selfprobe.go).
const (
	linuxProbeHost = "nrprobe0"
	linuxProbePeer = "nrprobe1"
	// linuxProbeRulePref places the probe's routing rule before every other
	// rule but the local table (0).
	linuxProbeRulePref = "1"
)

var probeMu sync.Mutex

// ProbeLocal sends a SYN to each port of ip through a temporary veth pair,
// so the connection arrives on a real interface and passes the input rules.
func (e *LinuxEngine) ProbeLocal(ctx context.Context, ip string, ports []int, timeout time.Duration) ([]PortProbe, error) {
	target := net.ParseIP(ip).To4()
	if target == nil {
		return nil, fmt.Errorf("no IPv4 address to test")
	}
	if len(ports) == 0 {
		return nil, nil
	}
	probeMu.Lock()
	defer probeMu.Unlock()
	ipCmd := func(c context.Context, args ...string) error {
		out, err := e.run(c, 10*time.Second, "ip", args...)
		if err != nil {
			return fmt.Errorf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	// The host answers from its own address, and policy rules for that
	// source (NetRiser's management table, VPN clients) would send the
	// answer elsewhere; a rule ahead of them keeps the probe network on the
	// main table, where the pair's connected route is.
	probeNet := fmt.Sprintf("%s/%d", probeHostIP.Mask(net.CIDRMask(probePrefixLen, 32)), probePrefixLen)
	ruleArgs := []string{"rule", "del", "pref", linuxProbeRulePref, "to", probeNet, "lookup", "main"}
	cleanup := func() {
		c := context.Background()
		for i := 0; i < 5 && ipCmd(c, ruleArgs...) == nil; i++ {
		}
		_ = ipCmd(c, "link", "del", linuxProbeHost)
	}
	cleanup()
	if err := ipCmd(ctx, "link", "add", linuxProbeHost, "type", "veth", "peer", "name", linuxProbePeer); err != nil {
		return nil, err
	}
	defer cleanup()
	addRule := append([]string{"rule", "add"}, ruleArgs[2:]...)
	if err := ipCmd(ctx, addRule...); err != nil {
		return nil, err
	}
	for _, ifc := range []string{linuxProbeHost, linuxProbePeer} {
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+ifc+"/disable_ipv6", []byte("1"), 0644)
	}
	for _, args := range [][]string{
		{"addr", "add", fmt.Sprintf("%s/%d", probeHostIP, probePrefixLen), "dev", linuxProbeHost},
		{"link", "set", linuxProbePeer, "up"},
		{"link", "set", linuxProbeHost, "up"},
	} {
		if err := ipCmd(ctx, args...); err != nil {
			return nil, err
		}
	}
	hostIf, err := net.InterfaceByName(linuxProbeHost)
	if err != nil {
		return nil, err
	}
	peerIf, err := net.InterfaceByName(linuxProbePeer)
	if err != nil {
		return nil, err
	}
	link, err := openPacketLink(peerIf.Index)
	if err != nil {
		return nil, err
	}
	defer link.Close()
	waitOperUp(linuxProbeHost, 2*time.Second)
	return runSelfProbe(ctx, link, peerIf.HardwareAddr, hostIf.HardwareAddr, target, ports, timeout), nil
}

func waitOperUp(ifc string, max time.Duration) {
	end := time.Now().Add(max)
	for time.Now().Before(end) {
		if b, err := os.ReadFile("/sys/class/net/" + ifc + "/operstate"); err == nil && strings.TrimSpace(string(b)) == "up" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// packetLink is an AF_PACKET socket bound to one interface.
type packetLink struct {
	fd      int
	ifindex int
}

func openPacketLink(ifindex int) (*packetLink, error) {
	proto := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind packet socket: %w", err)
	}
	return &packetLink{fd: fd, ifindex: ifindex}, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (l *packetLink) ReadFrame(deadline time.Time) ([]byte, error) {
	buf := make([]byte, 2048)
	for {
		d := time.Until(deadline)
		if d <= 0 {
			return nil, os.ErrDeadlineExceeded
		}
		tv := unix.NsecToTimeval(d.Nanoseconds())
		if err := unix.SetsockoptTimeval(l.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return nil, err
		}
		n, from, err := unix.Recvfrom(l.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil, os.ErrDeadlineExceeded
			}
			return nil, err
		}
		if sll, ok := from.(*unix.SockaddrLinklayer); ok && sll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		return append([]byte(nil), buf[:n]...), nil
	}
}

func (l *packetLink) WriteFrame(frame []byte) error {
	var addr [8]byte
	copy(addr[:], frame[0:6])
	return unix.Sendto(l.fd, frame, 0, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: l.ifindex, Halen: 6, Addr: addr})
}

func (l *packetLink) Close() error { return unix.Close(l.fd) }
