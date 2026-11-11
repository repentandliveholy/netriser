package netengine

import (
	"bufio"
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

type RouteEntry struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"dev"`
	Metric      int    `json:"metric"`
	Table       string `json:"table,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

type LinuxIPRouteJSON struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	Metric   int    `json:"metric"`
	Table    string `json:"table"`
	Protocol string `json:"protocol"`
}

type LinuxAddrInfoJSON struct {
	Family string `json:"family"`
	Local  string `json:"local"`
	Scope  string `json:"scope"`
}

type LinuxAddrDeviceJSON struct {
	IfName    string              `json:"ifname"`
	AddrInfo  []LinuxAddrInfoJSON `json:"addr_info"`
	OperState string              `json:"operstate"`
}

// ParseLinuxRoutesJSON parses structured output of `ip -j -4 route show`.
func ParseLinuxRoutesJSON(data []byte) ([]RouteEntry, error) {
	var items []LinuxIPRouteJSON
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	res := make([]RouteEntry, len(items))
	for i, it := range items {
		res[i] = RouteEntry{
			Destination: it.Dst,
			Gateway:     it.Gateway,
			Interface:   it.Dev,
			Metric:      it.Metric,
			Table:       it.Table,
			Protocol:    it.Protocol,
		}
	}
	return res, nil
}

// ParseLinuxRoutesText parses text output of `ip -4 route show`.
func ParseLinuxRoutesText(output string) []RouteEntry {
	var res []RouteEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		entry := RouteEntry{
			Destination: fields[0],
		}
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				entry.Gateway = fields[i+1]
			case "dev":
				entry.Interface = fields[i+1]
			case "metric":
				if m, err := strconv.Atoi(fields[i+1]); err == nil {
					entry.Metric = m
				}
			case "table":
				entry.Table = fields[i+1]
			case "proto":
				entry.Protocol = fields[i+1]
			}
		}
		res = append(res, entry)
	}
	return res
}

// ParseLinuxAddrJSON extracts primary IPv4 from `ip -j -4 addr show dev <dev>`.
func ParseLinuxAddrJSON(data []byte) string {
	var devs []LinuxAddrDeviceJSON
	if err := json.Unmarshal(data, &devs); err != nil {
		return ""
	}
	for _, dev := range devs {
		for _, a := range dev.AddrInfo {
			if (a.Family == "inet" || a.Family == "") && a.Scope == "global" {
				if ip := net.ParseIP(a.Local); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
		}
	}
	return ""
}

// ParseLinuxAddrText extracts primary IPv4 from `ip -4 -o addr show dev <dev> scope global`.
func ParseLinuxAddrText(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ipWithMask := fields[3]
			ip, _, err := net.ParseCIDR(ipWithMask)
			if err == nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}

type LinuxRuleEntry struct {
	Priority int
	Selector string
	Action   string
	Raw      string
}

// ParseLinuxRules parses text output of `ip rule show`.
func ParseLinuxRules(output string) []LinuxRuleEntry {
	var rules []LinuxRuleEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		prio := 0
		rest := line
		if len(parts) == 2 {
			if p, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
				prio = p
			}
			rest = strings.TrimSpace(parts[1])
		}
		rules = append(rules, LinuxRuleEntry{
			Priority: prio,
			Raw:      line,
			Selector: rest,
		})
	}
	return rules
}

// ParseDarwinRouteGetDefault extracts gateway and interface from `route -n get default`.
func ParseDarwinRouteGetDefault(output string) (gateway, iface string) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				gateway = parts[1]
			}
		} else if strings.HasPrefix(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				iface = parts[1]
			}
		}
	}
	return gateway, iface
}

type DarwinRouteEntry struct {
	Destination string
	Gateway     string
	Interface   string
	Flags       string
}

// ParseDarwinNetstat parses `netstat -rn -f inet` output.
func ParseDarwinNetstat(output string) []DarwinRouteEntry {
	var res []DarwinRouteEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	inTable := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Destination") && strings.Contains(line, "Gateway") {
			inTable = true
			continue
		}
		if !inTable || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			res = append(res, DarwinRouteEntry{
				Destination: fields[0],
				Gateway:     fields[1],
				Flags:       fields[2],
				Interface:   fields[3],
			})
		}
	}
	return res
}
