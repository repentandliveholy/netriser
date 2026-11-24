package netengine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Inventory parsing and ruleset copies for local block recovery on Linux
// and macOS (see blockers.go). Kept free of build tags so it is tested on
// every system.

// --- listening sockets -------------------------------------------------------

// ParseProcNetTCP reads /proc/net/tcp or /proc/net/tcp6 into port -> local
// addresses in the LISTEN state.
func ParseProcNetTCP(text string, v6 bool) map[int][]string {
	res := map[int][]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		hostPort := strings.SplitN(f[1], ":", 2)
		if len(hostPort) != 2 {
			continue
		}
		port, err := strconv.ParseUint(hostPort[1], 16, 16)
		if err != nil {
			continue
		}
		raw, err := hex.DecodeString(hostPort[0])
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		// The kernel prints each 32-bit word in host (little-endian) order.
		ip := make(net.IP, len(raw))
		for i := 0; i < len(raw); i += 4 {
			ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		addr := ip.String()
		if v6 && ip.Equal(net.IPv6unspecified) {
			addr = "::"
		} else if v4 := ip.To4(); v4 != nil && v6 {
			addr = v4.String()
		}
		res[int(port)] = append(res[int(port)], addr)
	}
	return res
}

// ParseDarwinNetstatListening reads `netstat -an -p tcp` (macOS) into port
// -> local addresses in the LISTEN state.
func ParseDarwinNetstatListening(text string) map[int][]string {
	res := map[int][]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || f[len(f)-1] != "LISTEN" {
			continue
		}
		local := f[3]
		i := strings.LastIndex(local, ".")
		if i <= 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		addr := local[:i]
		if j := strings.Index(addr, "%"); j >= 0 {
			addr = addr[:j]
		}
		if addr == "*" {
			switch f[0] {
			case "tcp4":
				res[port] = append(res[port], "0.0.0.0")
			case "tcp6":
				res[port] = append(res[port], "::")
			default: // tcp46
				res[port] = append(res[port], "0.0.0.0", "::")
			}
			continue
		}
		res[port] = append(res[port], addr)
	}
	return res
}

// --- nftables and iptables ---------------------------------------------------

// RulesTable is one table of a packet filter ruleset.
type RulesTable struct {
	// Name is "inet filter" for nftables, "filter" for iptables-save.
	Name string
	// Text is the table as listed, loadable again.
	Text string
}

// SplitNftTables splits `nft list ruleset` output into its tables.
func SplitNftTables(text string) []RulesTable {
	var out []RulesTable
	var cur *RulesTable
	var b strings.Builder
	depth := 0
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if cur == nil {
			if strings.HasPrefix(trim, "table ") && strings.HasSuffix(trim, "{") {
				name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trim, "table "), "{"))
				cur = &RulesTable{Name: name}
				b.Reset()
				depth = 0
			} else {
				continue
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			cur.Text = b.String()
			out = append(out, *cur)
			cur = nil
		}
	}
	return out
}

// churnChain matches chains rewritten by container runtimes, VPN clients and
// ban tools as they run; they are left out of the fingerprint so their
// routine changes do not make a table look new.
var churnChain = regexp.MustCompile(`^(?i)(docker|kube-|cni-|cali-|flannel|ts-|f2b-|fail2ban|crowdsec|libvirt|lxd|incus|podman|netavark|zt|nebula|netbird|wg)`)

// NftRelevant reports whether a table filters traffic to or from the host:
// it has a base chain on the input, output, prerouting or ingress hook.
func NftRelevant(t RulesTable) bool {
	return regexp.MustCompile(`hook (input|output|prerouting|ingress)\b`).MatchString(t.Text)
}

var (
	nftChainStart = regexp.MustCompile(`^\s*chain\s+(\S+)\s*\{`)
	nftComment    = regexp.MustCompile(`(?m)^\s*#.*$`)
	nftHandle     = regexp.MustCompile(`\s+# handle \d+`)
	nftCounter    = regexp.MustCompile(`counter packets \d+ bytes \d+`)
	nftElements   = regexp.MustCompile(`(?s)elements = \{.*?\}`)
)

// NftFingerprint hashes a table without counters, set elements, comments and
// churning chains.
func NftFingerprint(t RulesTable) string {
	var b strings.Builder
	skip := 0
	for _, line := range strings.Split(t.Text, "\n") {
		if skip > 0 {
			skip += strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}
		if m := nftChainStart.FindStringSubmatch(line); m != nil && churnChain.MatchString(m[1]) {
			skip = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	s := nftElements.ReplaceAllString(b.String(), "elements = {}")
	s = nftCounter.ReplaceAllString(s, "counter")
	s = nftHandle.ReplaceAllString(s, "")
	s = nftComment.ReplaceAllString(s, "")
	return fingerprint(s)
}

// SplitIptablesSave splits iptables-save output into its tables ("*filter"
// through "COMMIT").
func SplitIptablesSave(text string) []RulesTable {
	var out []RulesTable
	var cur *RulesTable
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trim, "*"):
			cur = &RulesTable{Name: strings.TrimPrefix(trim, "*")}
			b.Reset()
			b.WriteString(trim + "\n")
		case cur == nil || strings.HasPrefix(trim, "#") || trim == "":
		case trim == "COMMIT":
			b.WriteString("COMMIT\n")
			cur.Text = b.String()
			out = append(out, *cur)
			cur = nil
		default:
			b.WriteString(trim + "\n")
		}
	}
	return out
}

var iptCounters = regexp.MustCompile(`\[\d+:\d+\]`)

// IptablesFingerprint hashes a table without counters and churning chains.
// ok is false for a table that filters nothing (no rules, policies ACCEPT).
func IptablesFingerprint(t RulesTable) (fp string, ok bool) {
	var b strings.Builder
	for _, line := range strings.Split(t.Text, "\n") {
		switch {
		case strings.HasPrefix(line, ":"):
			f := strings.Fields(line)
			if len(f) >= 2 && churnChain.MatchString(strings.TrimPrefix(f[0], ":")) {
				continue
			}
			if len(f) >= 2 && f[1] != "ACCEPT" && f[1] != "-" {
				ok = true
			}
			b.WriteString(iptCounters.ReplaceAllString(line, "") + "\n")
		case strings.HasPrefix(line, "-A "):
			f := strings.Fields(line)
			if len(f) >= 2 && churnChain.MatchString(f[1]) {
				continue
			}
			ok = true
			b.WriteString(line + "\n")
		default:
			b.WriteString(line + "\n")
		}
	}
	return fingerprint(b.String()), ok
}

// EmptyIptablesTable returns a table with the built-in chains of t accepting
// everything and no rules, the iptables form of removing a table.
func EmptyIptablesTable(t RulesTable) string {
	var b strings.Builder
	b.WriteString("*" + t.Name + "\n")
	for _, line := range strings.Split(t.Text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasPrefix(f[0], ":") && f[1] != "-" {
			b.WriteString(f[0] + " ACCEPT [0:0]\n")
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(s), " ")))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// --- systemd -------------------------------------------------------------------

// UnitInfo is what `systemctl show` reports about a unit.
type UnitInfo struct {
	ID           string
	FragmentPath string
	Exec         string
}

// ParseSystemctlShow reads `systemctl show -p Id -p FragmentPath -p ExecStart
// ...` output for several units (blocks separated by blank lines).
func ParseSystemctlShow(text string) []UnitInfo {
	var out []UnitInfo
	var cur UnitInfo
	flush := func() {
		if cur.ID != "" {
			out = append(out, cur)
		}
		cur = UnitInfo{}
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch {
		case k == "Id":
			if cur.ID != "" {
				flush()
			}
			cur.ID = v
		case k == "FragmentPath":
			cur.FragmentPath = v
		case strings.HasPrefix(k, "Exec"):
			cur.Exec += " " + v
		}
	}
	flush()
	return out
}

// FirstColumn returns the first field of each non-empty line.
func FirstColumn(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, strings.TrimPrefix(f[0], "●"))
		}
	}
	return out
}

// knownFirewalls are services and daemons that load packet filter rules.
var knownFirewalls = regexp.MustCompile(`^(?i)(firewalld|ufw|nftables|iptables|ip6tables|ebtables|ipset|netfilter-persistent|iptables-persistent|shorewall6?|ferm|csf|lfd|opensnitch[d]?|fail2ban|crowdsec-firewall-bouncer|crowdsec|sshguard|denyhosts|apf|arno-iptables-firewall|firehol|vuurmuur|pf|murus|vallum|com\.obdev\.littlesnitch.*|at\.obdev\.littlesnitch.*|com\.objective-see\.lulu.*|com\.radiosilenceapp.*|.*firewall.*)(\.service)?$`)

// firewallCommands are programs whose use in a unit's commands means it
// loads packet filter rules.
var firewallCommands = regexp.MustCompile(`(?i)(^|[\s/;=])(nft|iptables|ip6tables|iptables-restore|ip6tables-restore|iptables-legacy|ebtables|arptables|ipset|pfctl|socketfilterfw|bpftool|xdp-loader|tc)(\s|$|;)`)

// IsFirewallUnit reports whether a unit or daemon loads packet filter rules.
func IsFirewallUnit(name, commands string) bool {
	return knownFirewalls.MatchString(name) || firewallCommands.MatchString(commands)
}

// --- kernel modules -------------------------------------------------------------

// ParseProcModules returns the module names in /proc/modules.
func ParseProcModules(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// ModuleUntrusted reports whether a module with these taint flags and
// signer is untrusted: loaded unsigned on a kernel that checks signatures
// (E), or built outside the kernel tree (O) without a signature.
func ModuleUntrusted(taint, signer string) bool {
	return strings.Contains(taint, "E") || (strings.Contains(taint, "O") && strings.TrimSpace(signer) == "")
}

// --- macOS ----------------------------------------------------------------------

// ParsePfStatus reads `pfctl -s info`; ok is false when the status is absent.
func ParsePfStatus(text string) (enabled, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "Status:" {
			return strings.EqualFold(f[1], "Enabled"), true
		}
	}
	return false, false
}

// ParseOnOff reads a socketfilterfw answer: enabled, disabled, or unknown.
func ParseOnOff(text string) (on, ok bool) {
	t := strings.ToLower(text)
	switch {
	case strings.Contains(t, "disabled") || strings.Contains(t, "state = 0") || strings.Contains(t, " off"):
		return false, true
	case strings.Contains(t, "enabled") || strings.Contains(t, "set to block all") || strings.Contains(t, "state = 1") || strings.Contains(t, "state = 2") || strings.Contains(t, " on"):
		return true, true
	}
	return false, false
}

// ParseLaunchctlList returns the labels in `launchctl list` output.
func ParseLaunchctlList(text string) map[string]bool {
	res := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[2] != "Label" {
			res[f[2]] = true
		}
	}
	return res
}

// ParseLaunchctlDisabled returns the labels marked disabled in `launchctl
// print-disabled system`.
func ParseLaunchctlDisabled(text string) map[string]bool {
	res := map[string]bool{}
	re := regexp.MustCompile(`"([^"]+)"\s*=>\s*(true|disabled)`)
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		res[m[1]] = true
	}
	return res
}

// LaunchdPlist is the part of a launchd property list NetRiser reads.
type LaunchdPlist struct {
	Label            string   `json:"Label"`
	Program          string   `json:"Program"`
	ProgramArguments []string `json:"ProgramArguments"`
	Disabled         bool     `json:"Disabled"`
}

// ParseLaunchdJSON reads `plutil -convert json -o - file` output.
func ParseLaunchdJSON(text string) (LaunchdPlist, error) {
	var p LaunchdPlist
	err := json.Unmarshal([]byte(text), &p)
	return p, err
}

// ParseNetworkExtensions returns the enabled network extensions in
// `systemextensionsctl list`: bundle id -> version.
func ParseNetworkExtensions(text string) map[string]string {
	res := map[string]string{}
	network := false
	re := regexp.MustCompile(`\s([A-Za-z0-9][\w.-]+\.[\w.-]+)\s+\(([^)]*)\)`)
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "---") {
			network = strings.Contains(line, "network_extension")
			continue
		}
		if !network || !strings.Contains(line, "[activated enabled]") {
			continue
		}
		if m := re.FindStringSubmatch(line); m != nil {
			res[m[1]] = m[2]
		}
	}
	return res
}

// --- ruleset copies -------------------------------------------------------------

// rulesStore keeps copies of the rulesets of a working host (work/) and of
// what recovery replaced (backup/), under the state directory.
type rulesStore struct{ dir string }

const keepVersions = 5

func safeName(name string) string {
	return regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(name, "_")
}

// save records the ruleset of a working host unless its newest copy has
// the same fingerprint.
func (s rulesStore) save(name, fp, text string, now time.Time) error {
	dir := filepath.Join(s.dir, "work")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	versions := s.versions(name)
	if len(versions) > 0 && versions[len(versions)-1].fp == fp {
		return nil
	}
	file := filepath.Join(dir, fmt.Sprintf("%s@%d@%s.rules", safeName(name), now.Unix(), strings.TrimPrefix(fp, "sha256:")))
	if err := os.WriteFile(file, []byte(text), 0600); err != nil {
		return err
	}
	versions = s.versions(name)
	for len(versions) > keepVersions {
		os.Remove(versions[0].path)
		versions = versions[1:]
	}
	return nil
}

type rulesVersion struct {
	path string
	at   time.Time
	fp   string
}

func (s rulesStore) versions(name string) []rulesVersion {
	prefix := safeName(name) + "@"
	entries, _ := os.ReadDir(filepath.Join(s.dir, "work"))
	var out []rulesVersion
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ".rules") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(n, prefix), ".rules"), "@")
		if len(parts) != 2 {
			continue
		}
		sec, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, rulesVersion{path: filepath.Join(s.dir, "work", n), at: time.Unix(sec, 0), fp: "sha256:" + parts[1]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return out
}

// working returns the newest copy saved before the given time whose
// fingerprint differs from current.
func (s rulesStore) working(name, current string, before time.Time) (string, bool) {
	versions := s.versions(name)
	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
		if v.fp == current || (!before.IsZero() && !v.at.Before(before)) {
			continue
		}
		data, err := os.ReadFile(v.path)
		if err != nil {
			continue
		}
		return string(data), true
	}
	return "", false
}

func (s rulesStore) backupPath(name string) string {
	return filepath.Join(s.dir, "backup", safeName(name)+".rules")
}

func (s rulesStore) writeBackup(name, text string) error {
	if err := os.MkdirAll(filepath.Join(s.dir, "backup"), 0700); err != nil {
		return err
	}
	return os.WriteFile(s.backupPath(name), []byte(text), 0600)
}

// writeTemp writes text to a file for a command to load.
func (s rulesStore) writeTemp(text string) (string, error) {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(s.dir, "load-*.rules")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(text)
	return f.Name(), err
}
