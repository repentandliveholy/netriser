package netengine

import (
	"net"
	"strings"
)

// interfaceIPv4 returns the first usable IPv4 address of a network interface
// by its name (on Windows, the adapter's alias such as "Ethernet 3"), or "".
// It asks the operating system directly, so it works while the network is
// down and needs no external command.
func interfaceIPv4(name string) string {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	return firstUsableIPv4(addrs)
}

func firstUsableIPv4(addrs []net.Addr) string {
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if v4 := ip.To4(); v4 != nil && !v4.IsLinkLocalUnicast() && !v4.IsLoopback() && !v4.IsUnspecified() {
			return v4.String()
		}
	}
	return ""
}

// firstIPv4Line returns the first line of command output that is an IPv4
// address. Output also carries stderr, where PowerShell may write progress
// or warnings, so the whole output is not expected to be just the address.
func firstIPv4Line(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if ip := net.ParseIP(line); ip != nil && ip.To4() != nil {
			return ip.To4().String()
		}
	}
	return ""
}

// commandDetail formats command output for an error message: ": <output>",
// on one line and shortened, or "" when there is none.
func commandDetail(out string) string {
	out = strings.Join(strings.Fields(out), " ")
	if out == "" {
		return ""
	}
	const max = 300
	if len(out) > max {
		out = out[:max] + "..."
	}
	return ": " + out
}
