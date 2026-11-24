//go:build darwin

package netengine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The temporary feth pair of the self-probe (see selfprobe.go). feth is the
// macOS fake Ethernet pair; a frame written with BPF on one side arrives on
// the other.
const (
	darwinProbeHost = "feth3170"
	darwinProbePeer = "feth3171"
)

var probeMu sync.Mutex

// ProbeLocal sends a SYN to each port of ip through a temporary feth pair,
// so the connection arrives on a real interface and passes pf and the
// application firewall.
func (e *DarwinEngine) ProbeLocal(ctx context.Context, ip string, ports []int, timeout time.Duration) ([]PortProbe, error) {
	target := net.ParseIP(ip).To4()
	if target == nil {
		return nil, fmt.Errorf("no IPv4 address to test")
	}
	if len(ports) == 0 {
		return nil, nil
	}
	probeMu.Lock()
	defer probeMu.Unlock()
	ifconfig := func(c context.Context, args ...string) error {
		out, err := e.run(c, 10*time.Second, "/sbin/ifconfig", args...)
		if err != nil {
			return fmt.Errorf("ifconfig %s: %v %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	destroy := func() {
		_ = ifconfig(context.Background(), darwinProbeHost, "destroy")
		_ = ifconfig(context.Background(), darwinProbePeer, "destroy")
	}
	destroy()
	if err := ifconfig(ctx, darwinProbeHost, "create"); err != nil {
		return nil, err
	}
	defer destroy()
	mask := net.IP(net.CIDRMask(probePrefixLen, 32)).String()
	for _, args := range [][]string{
		{darwinProbePeer, "create"},
		{darwinProbeHost, "peer", darwinProbePeer},
		{darwinProbeHost, "inet", probeHostIP.String(), "netmask", mask, "up"},
		{darwinProbePeer, "up"},
	} {
		if err := ifconfig(ctx, args...); err != nil {
			return nil, err
		}
	}
	hostIf, err := net.InterfaceByName(darwinProbeHost)
	if err != nil {
		return nil, err
	}
	peerIf, err := net.InterfaceByName(darwinProbePeer)
	if err != nil {
		return nil, err
	}
	link, err := openBPF(darwinProbePeer)
	if err != nil {
		return nil, err
	}
	defer link.Close()
	// With net.inet.ip.check_interface=1 (strong host model) macOS accepts a
	// packet for the address of en0 only on en0, so the probe asks for the
	// pair's own address instead: the listening services bound to all
	// addresses answer there, and pf and the application firewall filter
	// that interface as any other.
	if v, err := e.run(ctx, 5*time.Second, "/usr/sbin/sysctl", "-n", "net.inet.ip.check_interface"); err == nil && strings.TrimSpace(v) != "0" {
		target = probeHostIP
	}
	return runSelfProbe(ctx, link, peerIf.HardwareAddr, hostIf.HardwareAddr, target, ports, timeout), nil
}

// bpfLink reads and writes frames on one interface through /dev/bpf.
type bpfLink struct {
	fd      int
	buf     []byte
	pending [][]byte
}

func openBPF(ifname string) (*bpfLink, error) {
	var fd int
	var err error
	for i := 0; i < 256; i++ {
		fd, err = unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err == nil || !errors.Is(err, unix.EBUSY) {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open /dev/bpf: %w", err)
	}
	l := &bpfLink{fd: fd}
	fail := func(what string, err error) (*bpfLink, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("bpf %s: %w", what, err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, 1<<16); err != nil {
		return fail("buffer", err)
	}
	var ifr [32]byte
	copy(ifr[:15], ifname)
	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr[0])); err != nil {
		return fail("attach to "+ifname, err)
	}
	for _, opt := range []uint{unix.BIOCIMMEDIATE, unix.BIOCSHDRCMPLT} {
		if err := unix.IoctlSetPointerInt(fd, opt, 1); err != nil {
			return fail("options", err)
		}
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSSEESENT, 0); err != nil {
		return fail("options", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil || n <= 0 {
		n = 1 << 16
	}
	l.buf = make([]byte, n)
	return l, nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func (l *bpfLink) ReadFrame(deadline time.Time) ([]byte, error) {
	for len(l.pending) == 0 {
		d := time.Until(deadline)
		if d <= 0 {
			return nil, os.ErrDeadlineExceeded
		}
		tv := unix.NsecToTimeval(d.Nanoseconds())
		if err := ioctlPtr(l.fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
			return nil, err
		}
		n, err := unix.Read(l.fd, l.buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return nil, err
		}
		l.pending = splitBPF(l.buf[:n])
	}
	f := l.pending[0]
	l.pending = l.pending[1:]
	return f, nil
}

// splitBPF splits a BPF read into frames. Each record is a bpf_hdr (struct
// timeval32, caplen, datalen, hdrlen) followed by the frame, aligned to 4.
func splitBPF(b []byte) [][]byte {
	var out [][]byte
	for off := 0; off+18 <= len(b); {
		caplen := int(binary.LittleEndian.Uint32(b[off+8:]))
		hdrlen := int(binary.LittleEndian.Uint16(b[off+16:]))
		if hdrlen == 0 || off+hdrlen+caplen > len(b) {
			break
		}
		out = append(out, append([]byte(nil), b[off+hdrlen:off+hdrlen+caplen]...))
		off += (hdrlen + caplen + 3) &^ 3
	}
	return out
}

func (l *bpfLink) WriteFrame(frame []byte) error {
	_, err := unix.Write(l.fd, frame)
	return err
}

func (l *bpfLink) Close() error { return unix.Close(l.fd) }
