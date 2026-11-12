package canary

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProtoPing marks an access check by ICMP echo (a target without a port).
const ProtoPing ProbeProtocol = "ping"

// probeAccess checks an access address (mesh_canaries): "host" is pinged and
// "host:port" is connected to over TCP. A refused connection also counts:
// the host answered, only that port is closed.
func (c *Checker) probeAccess(ctx context.Context, target string, start time.Time) TargetResult {
	res := TargetResult{Target: target, Group: GroupMesh}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = strings.Trim(target, "[]"), ""
	}
	if port == "" {
		res.Protocol = ProtoPing
		res.Error = ping(ctx, runtime.GOOS, host, c.cfg.ProbeTimeout())
	} else {
		res.Protocol = ProtoTCP
		d := net.Dialer{Timeout: c.cfg.ProbeTimeout()}
		conn, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if derr == nil {
			_ = conn.Close()
		} else if !connectionRefused(derr) {
			res.Error = derr
		}
	}
	if res.Error != nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		res.Cancelled = true
	}
	res.Success = res.Error == nil
	if res.Success {
		res.Latency = time.Since(start)
	}
	return res
}

func connectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "refused")
}

// pingCommand builds a single echo request with the system ping, which works
// without raw-socket code on Linux, macOS and Windows.
func pingCommand(goos, host string, timeout time.Duration) []string {
	secs := max(1, int(timeout.Round(time.Second)/time.Second))
	v6 := strings.Contains(host, ":")
	switch goos {
	case "windows":
		args := []string{"ping", "-n", "1", "-w", strconv.Itoa(secs * 1000)}
		if v6 {
			args = append(args, "-6")
		}
		return append(args, host)
	case "darwin":
		if v6 {
			return []string{"ping6", "-c", "1", host}
		}
		return []string{"ping", "-c", "1", "-t", strconv.Itoa(secs), host}
	default:
		return []string{"ping", "-c", "1", "-W", strconv.Itoa(secs), host}
	}
}

// pingAnswered interprets the result. Windows ping exits 0 for "Destination
// host unreachable" replies from a router, so an IPv4 reply must carry TTL=.
func pingAnswered(goos, host, output string, err error) bool {
	if err != nil {
		return false
	}
	if goos == "windows" && !strings.Contains(host, ":") {
		return strings.Contains(strings.ToUpper(output), "TTL=")
	}
	return true
}

func ping(ctx context.Context, goos, host string, timeout time.Duration) error {
	if host == "" {
		return errors.New("empty address")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	args := pingCommand(goos, host, timeout)
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if pingAnswered(goos, host, string(out), err) {
		return nil
	}
	return fmt.Errorf("no ping reply from %s", host)
}
