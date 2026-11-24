package netengine

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// fakeHostStack plays the host side of the pair: it asks for the peer's MAC
// first (as a kernel would before answering), then answers each SYN as its
// firewall decides.
type fakeHostStack struct {
	t        *testing.T
	hostMAC  net.HardwareAddr
	peerMAC  net.HardwareAddr
	target   net.IP
	behavior map[int]string // port -> "open", "drop", "reset", "icmp"
	queue    [][]byte
	known    bool // peer MAC learned from an ARP reply
	pending  [][]byte
	rsts     int
	syns     int
}

func (h *fakeHostStack) ReadFrame(deadline time.Time) ([]byte, error) {
	if len(h.queue) == 0 {
		return nil, os.ErrDeadlineExceeded
	}
	f := h.queue[0]
	h.queue = h.queue[1:]
	return f, nil
}

func (h *fakeHostStack) Close() error { return nil }

func (h *fakeHostStack) WriteFrame(f []byte) error {
	switch binary.BigEndian.Uint16(f[12:14]) {
	case 0x0806:
		a := f[14:]
		if binary.BigEndian.Uint16(a[6:8]) != 2 || net.HardwareAddr(a[8:14]).String() != h.peerMAC.String() || !net.IP(a[14:18]).Equal(probePeerIP) {
			h.t.Fatalf("bad ARP reply % x", f)
		}
		h.known = true
		h.queue = append(h.queue, h.pending...)
		h.pending = nil
		return nil
	case 0x0800:
	default:
		h.t.Fatalf("unexpected ethertype in % x", f)
	}
	ip := f[14:34]
	if checksum(ip, 0) != 0 {
		h.t.Fatalf("bad IP checksum")
	}
	tcp := f[34:]
	if checksum(tcp, pseudoHeaderSum(ip[12:16], ip[16:20], 6, len(tcp))) != 0 {
		h.t.Fatalf("bad TCP checksum")
	}
	if net.HardwareAddr(f[0:6]).String() != h.hostMAC.String() || !net.IP(ip[16:20]).Equal(h.target) {
		h.t.Fatalf("frame not addressed to the host")
	}
	sport, dport := binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	if tcp[13]&tcpRST != 0 {
		h.rsts++
		return nil
	}
	h.syns++
	var reply []byte
	switch h.behavior[int(dport)] {
	case "open":
		reply = buildTCP(h.hostMAC, h.peerMAC, h.target, probePeerIP, dport, sport, 777, seq+1, tcpSYN|tcpACK, true)
	case "reset":
		reply = buildTCP(h.hostMAC, h.peerMAC, h.target, probePeerIP, dport, sport, 0, seq+1, tcpRST|tcpACK, false)
	case "icmp":
		reply = make([]byte, 14+20+8+28)
		copy(reply[0:6], h.peerMAC)
		copy(reply[6:12], h.hostMAC)
		binary.BigEndian.PutUint16(reply[12:14], 0x0800)
		r := reply[14:]
		r[0], r[9] = 0x45, 1
		copy(r[12:16], h.target)
		copy(r[16:20], probePeerIP)
		r[20], r[21] = 3, 13 // communication administratively prohibited
		copy(r[28:], f[14:14+28])
	default:
		return nil
	}
	if !h.known {
		h.pending = append(h.pending, reply)
		h.queue = append(h.queue, arpRequest(h.hostMAC, probeHostIP, probePeerIP))
		return nil
	}
	h.queue = append(h.queue, reply)
	return nil
}

func arpRequest(mac net.HardwareAddr, from, who net.IP) []byte {
	f := make([]byte, 42)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:14], 0x0806)
	a := f[14:]
	binary.BigEndian.PutUint16(a[0:2], 1)
	binary.BigEndian.PutUint16(a[2:4], 0x0800)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:8], 1)
	copy(a[8:14], mac)
	copy(a[14:18], from.To4())
	copy(a[24:28], who.To4())
	return f
}

func TestRunSelfProbe(t *testing.T) {
	host := &fakeHostStack{
		t:        t,
		hostMAC:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		peerMAC:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		target:   net.IPv4(192, 0, 2, 10).To4(),
		behavior: map[int]string{22: "open", 3389: "drop", 80: "reset", 443: "icmp"},
	}
	res := runSelfProbe(context.Background(), host, host.peerMAC, host.hostMAC, host.target, []int{3389, 22, 80, 443}, 1500*time.Millisecond)
	got := LocalAccessResult{Probes: res}.Summary()
	if want := "22 ok, 80 reset, 443 rejected (icmp code 13), 3389 timeout"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if host.rsts != 1 {
		t.Fatalf("half-open connection not closed: %d resets", host.rsts)
	}
	// The silent port was asked again after a second.
	if host.syns < 5 {
		t.Fatalf("no retransmission: %d SYNs", host.syns)
	}
}

func TestProbeTargets(t *testing.T) {
	l := map[int][]string{22: {"0.0.0.0"}, 3389: {"127.0.0.1"}, 80: {"192.0.2.10"}}
	if got := probeTargets("192.0.2.10", []int{22, 3389, 80, 443}, l); len(got) != 2 || got[0] != 22 || got[1] != 80 {
		t.Fatalf("got %v", got)
	}
}
