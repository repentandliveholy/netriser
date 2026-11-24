package netengine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

// Self-probe over a virtual Ethernet pair (Linux veth, macOS feth).
//
// Connecting to the host's own address goes over loopback on Linux and
// macOS, and firewalls usually accept loopback ("iifname lo accept", pf "set
// skip on lo0"). So the host side of a temporary pair gets probeHostIP and
// the other side is driven directly: a TCP SYN to the host's address is
// written there, arrives on a real interface and passes the input rules like
// a remote connection. A SYN-ACK means the port accepts; silence, a reset or
// an ICMP error means a filter on the host stopped it.

var (
	probeHostIP = net.IPv4(198, 18, 231, 1).To4() // benchmark range (RFC 2544)
	probePeerIP = net.IPv4(198, 18, 231, 2).To4()
)

const probePrefixLen = 30

// rawLink sends and receives Ethernet frames on the peer side of the pair.
type rawLink interface {
	// ReadFrame returns the next frame, or os.ErrDeadlineExceeded at the
	// deadline.
	ReadFrame(deadline time.Time) ([]byte, error)
	WriteFrame(frame []byte) error
	Close() error
}

type probeState struct {
	port    int
	srcPort uint16
	seq     uint32
	done    bool
	res     PortProbe
}

// runSelfProbe sends a SYN to target on each port through link and waits
// for the answers. peerMAC is the MAC of the driven side, hostMAC that of the
// host side.
func runSelfProbe(ctx context.Context, link rawLink, peerMAC, hostMAC net.HardwareAddr, target net.IP, ports []int, timeout time.Duration) []PortProbe {
	target = target.To4()
	states := map[uint16]*probeState{}
	var order []*probeState
	base := 40000 + uint16(randUint32()%20000)
	for i, port := range ports {
		st := &probeState{port: port, srcPort: base + uint16(i), seq: randUint32(), res: PortProbe{Port: port}}
		states[st.srcPort] = st
		order = append(order, st)
	}
	send := func() {
		for _, st := range order {
			if !st.done {
				_ = link.WriteFrame(buildTCP(peerMAC, hostMAC, probePeerIP, target, st.srcPort, uint16(st.port), st.seq, 0, tcpSYN, true))
			}
		}
	}
	send()
	end := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(end) {
		end = dl
	}
	resend := time.Now().Add(time.Second)
	for remaining(order) > 0 && time.Now().Before(end) && ctx.Err() == nil {
		wait := end
		if resend.Before(wait) {
			wait = resend
		}
		frame, err := link.ReadFrame(wait)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if !time.Now().Before(resend) {
					send()
					resend = time.Now().Add(time.Second)
				}
				continue
			}
			break
		}
		handleProbeFrame(link, frame, peerMAC, target, states)
	}
	out := make([]PortProbe, 0, len(order))
	for _, st := range order {
		if !st.done {
			st.res.Error = "timeout"
		}
		out = append(out, st.res)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func remaining(sts []*probeState) int {
	n := 0
	for _, st := range sts {
		if !st.done {
			n++
		}
	}
	return n
}

func handleProbeFrame(link rawLink, frame []byte, peerMAC net.HardwareAddr, target net.IP, states map[uint16]*probeState) {
	if len(frame) < 14 || net.HardwareAddr(frame[6:12]).String() == peerMAC.String() {
		return // too short, or our own frame seen on the way out
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0806:
		if reply := arpReply(frame, peerMAC, probePeerIP); reply != nil {
			_ = link.WriteFrame(reply)
		}
	case 0x0800:
		ip := frame[14:]
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return
		}
		ihl := int(ip[0]&0x0f) * 4
		if len(ip) < ihl || !net.IP(ip[16:20]).Equal(probePeerIP) {
			return
		}
		switch ip[9] {
		case 6:
			tcp := ip[ihl:]
			if len(tcp) < 20 || !net.IP(ip[12:16]).Equal(target) {
				return
			}
			st := states[binary.BigEndian.Uint16(tcp[2:4])]
			if st == nil || st.done || int(binary.BigEndian.Uint16(tcp[0:2])) != st.port {
				return
			}
			flags := tcp[13]
			switch {
			case flags&(tcpSYN|tcpACK) == tcpSYN|tcpACK:
				st.done, st.res.OK = true, true
				// Close the half-open connection.
				ack := binary.BigEndian.Uint32(tcp[8:12])
				_ = link.WriteFrame(buildTCP(peerMAC, net.HardwareAddr(frame[6:12]), probePeerIP, target, st.srcPort, uint16(st.port), ack, 0, tcpRST, false))
			case flags&tcpRST != 0:
				st.done, st.res.Error = true, "reset"
			}
		case 1:
			icmp := ip[ihl:]
			// Destination unreachable carrying our SYN's IP header and ports.
			if len(icmp) < 8+20+4 || icmp[0] != 3 {
				return
			}
			inner := icmp[8:]
			innerLen := int(inner[0]&0x0f) * 4
			if len(inner) < innerLen+4 || inner[9] != 6 {
				return
			}
			st := states[binary.BigEndian.Uint16(inner[innerLen:innerLen+2])]
			if st == nil || st.done {
				return
			}
			st.done, st.res.Error = true, fmt.Sprintf("rejected (icmp code %d)", icmp[1])
		}
	}
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// buildTCP returns an Ethernet frame with an IPv4 TCP segment without data.
func buildTCP(src, dst net.HardwareAddr, srcIP, dstIP net.IP, sport, dport uint16, seq, ack uint32, flags byte, mss bool) []byte {
	tcpLen := 20
	if mss {
		tcpLen = 24
	}
	f := make([]byte, 14+20+tcpLen)
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+tcpLen))
	binary.BigEndian.PutUint16(ip[4:6], uint16(randUint32()))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // don't fragment
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip, 0))
	tcp := f[34:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = flags
	if flags&tcpRST == 0 {
		binary.BigEndian.PutUint16(tcp[14:16], 64240)
	}
	if mss {
		copy(tcp[20:24], []byte{2, 4, 0x05, 0xb4}) // MSS 1460
	}
	binary.BigEndian.PutUint16(tcp[16:18], checksum(tcp, pseudoHeaderSum(srcIP, dstIP, 6, len(tcp))))
	return f
}

// arpReply answers an ARP request for ip with mac; nil for anything else.
func arpReply(frame []byte, mac net.HardwareAddr, ip net.IP) []byte {
	a := frame[14:]
	if len(a) < 28 || binary.BigEndian.Uint16(a[0:2]) != 1 || binary.BigEndian.Uint16(a[2:4]) != 0x0800 ||
		a[4] != 6 || a[5] != 4 || binary.BigEndian.Uint16(a[6:8]) != 1 || !net.IP(a[24:28]).Equal(ip.To4()) {
		return nil
	}
	r := make([]byte, 14+28)
	copy(r[0:6], a[8:14]) // to the sender
	copy(r[6:12], mac)
	binary.BigEndian.PutUint16(r[12:14], 0x0806)
	b := r[14:]
	binary.BigEndian.PutUint16(b[0:2], 1)
	binary.BigEndian.PutUint16(b[2:4], 0x0800)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], 2)
	copy(b[8:14], mac)
	copy(b[14:18], ip.To4())
	copy(b[18:24], a[8:14])
	copy(b[24:28], a[14:18])
	return r
}

func pseudoHeaderSum(src, dst net.IP, proto byte, length int) uint32 {
	var sum uint32
	s, d := src.To4(), dst.To4()
	sum += uint32(s[0])<<8 | uint32(s[1])
	sum += uint32(s[2])<<8 | uint32(s[3])
	sum += uint32(d[0])<<8 | uint32(d[1])
	sum += uint32(d[2])<<8 | uint32(d[3])
	sum += uint32(proto)
	sum += uint32(length)
	return sum
}

// checksum is the Internet checksum of b (its checksum field zeroed), with
// an initial sum.
func checksum(b []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// probeTargets keeps the ports that listen on ip (see listensOn).
func probeTargets(ip string, ports []int, listening map[int][]string) []int {
	var out []int
	for _, p := range ports {
		if listensOn(listening[p], ip) {
			out = append(out, p)
		}
	}
	return out
}
