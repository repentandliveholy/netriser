package netengine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	t0      = time.Date(2026, 11, 4, 10, 17, 0, 0, time.UTC)
	longAgo = t0.AddDate(-1, 0, 0)
)

// derzh: what the RFW installation left on WS-OVS-010 on 2026-11-04.
func derzhComponents() []Component {
	return []Component{
		{Name: "RfwFilter", Kernel: true, Running: true, Start: StartDemand, Image: `C:\Program Files\rfw\rfwfilter.sys`, DependsOn: []string{"BFE"}, Changed: t0},
		{Name: "RfwService", Start: StartAuto, Image: `"C:\Program Files\rfw\rfw-service.exe" run`, DependsOn: []string{"RfwFilter"}, Changed: t0},
		{Name: "Tcpip", Kernel: true, Running: true, Start: StartBoot, Image: `System32\drivers\tcpip.sys`, Changed: longAgo},
		{Name: "afd", Kernel: true, Running: true, Start: StartSystem, Image: `\SystemRoot\system32\drivers\afd.sys`, Changed: longAgo},
		{Name: "rt640x64", Kernel: true, Start: StartDemand, Image: `\SystemRoot\System32\drivers\rt640x64.sys`, Device: true, Changed: longAgo},
		{Name: "Tailscale", Start: StartAuto, Image: `"C:\Program Files\Tailscale\tailscaled.exe"`, Changed: longAgo},
		{Name: "wintun", Kernel: true, Running: true, Start: StartDemand, Image: `\SystemRoot\System32\drivers\wintun.sys`, Changed: longAgo},
		{Name: "sshd", Start: StartAuto, Image: `C:\Windows\System32\OpenSSH\sshd.exe`, Changed: longAgo},
		{Name: "Dnscache", Start: StartAuto, Shared: true, Image: `%SystemRoot%\system32\svchost.exe -k NetworkService -p`, Changed: longAgo},
		{Name: "vmnetbridge", Kernel: true, Running: true, Start: StartAuto, Image: `system32\DRIVERS\vmnetbridge.sys`, Changed: longAgo},
		{Name: "OldUnsigned", Kernel: true, Running: true, Start: StartBoot, Image: `system32\DRIVERS\old.sys`, Changed: longAgo},
		// Found on a real Windows 11 host: Windows' own Bluetooth driver
		// (from a driver package, file shows no signature, not loaded) and
		// a hardware monitor's leftover driver whose file is gone.
		{Name: "BthA2dp", Kernel: true, Start: StartDemand, Package: true, Image: `\SystemRoot\System32\drivers\BthA2dp.sys`, Changed: longAgo},
		{Name: "InboxLoaded", Kernel: true, Running: true, Start: StartDemand, Package: true, Image: `\SystemRoot\System32\drivers\inbox.sys`, Changed: longAgo},
		{Name: "cpuz150", Kernel: true, Start: StartDemand, Image: `\??\C:\WINDOWS\temp\cpuz150\cpuz150_x64.sys`, Changed: longAgo},
		{Name: "GoneButLoaded", Kernel: true, Running: true, Start: StartDemand, Image: `\??\C:\Temp\gone.sys`, Changed: longAgo},
	}
}

func derzhSignatures() map[string]Signature {
	ms := Signature{Valid: true, Microsoft: true, Signer: "Microsoft Windows", Status: "Valid"}
	return map[string]Signature{
		"rfwfilter":     {Valid: false, Signer: "RFW Test Driver", Status: "UnknownError"},
		"rfwservice":    {Valid: false, Status: "NotSigned"},
		"tcpip":         ms,
		"afd":           ms,
		"rt640x64":      {Valid: false, Status: "NotSigned"},
		"tailscale":     {Valid: true, Signer: "Tailscale Inc.", Status: "Valid"},
		"wintun":        {Valid: true, Signer: "WireGuard LLC", Status: "Valid"},
		"sshd":          ms,
		"dnscache":      ms,
		"vmnetbridge":   {Valid: true, Signer: "VMware, Inc.", Status: "Valid"},
		"oldunsigned":   {Valid: false, Status: "NotSigned"},
		"btha2dp":       {Valid: false, Status: "NotSigned"},
		"inboxloaded":   {Valid: false, Status: "NotSigned"},
		"cpuz150":       {Valid: false, Status: "Missing"},
		"gonebutloaded": {Valid: false, Status: "Missing"},
	}
}

func names(bs []Blocker) string {
	var n []string
	for _, b := range bs {
		n = append(n, b.Name)
	}
	return strings.Join(n, ",")
}

// Without a snapshot (NetRiser installed after the damage), only the test
// signed RFW driver and the service that starts it are chosen; the service
// comes first so that the driver can be released.
func TestSelectBlockersWithoutSnapshotFindsRFW(t *testing.T) {
	p := BlockerPolicy{KnownGoodBefore: t0, Protected: DefaultProtectedComponents}
	got := SelectBlockers(derzhComponents(), derzhSignatures(), p)
	if names(got) != "RfwService,RfwFilter" {
		t.Fatalf("got %q, want RfwService,RfwFilter", names(got))
	}
	if !strings.Contains(got[0].Reason, "RfwFilter") || !strings.Contains(got[1].Reason, "trusted signature") {
		t.Fatalf("reasons: %+v", got)
	}
	// Device drivers, boot drivers, VPN drivers and validly signed third
	// party drivers are not even candidates for disabling.
	for _, c := range BlockerCandidates(derzhComponents(), p) {
		switch c.Name {
		case "rt640x64", "OldUnsigned", "wintun", "Tailscale", "sshd", "Dnscache", "Tcpip", "BthA2dp", "InboxLoaded", "cpuz150":
			t.Fatalf("%s must not be a candidate", c.Name)
		}
	}
}

// With a snapshot taken while the host worked, components new since then are
// chosen even when validly signed; long-known ones are not.
func TestSelectBlockersWithSnapshot(t *testing.T) {
	comps := derzhComponents()
	var known []Component
	for _, c := range comps {
		if !strings.HasPrefix(c.Name, "Rfw") {
			known = append(known, c)
		}
	}
	snap := &ComponentSnapshot{}
	MergeSnapshot(snap, known, t0.Add(-24*time.Hour))

	sigs := derzhSignatures()
	sigs["rfwfilter"] = Signature{Valid: true, Signer: "Microsoft Windows Hardware Compatibility Publisher", Status: "Valid"}
	p := BlockerPolicy{Snapshot: snap, KnownGoodBefore: t0.Add(-time.Hour), Protected: DefaultProtectedComponents}
	if got := names(SelectBlockers(comps, sigs, p)); got != "RfwService,RfwFilter" {
		t.Fatalf("got %q", got)
	}

	// A known driver moved from manual to automatic start is a change.
	comps[9].Start = StartAuto
	snap2 := &ComponentSnapshot{}
	old := append([]Component{}, known...)
	for i := range old {
		if old[i].Name == "vmnetbridge" {
			old[i].Start = StartDemand
		}
	}
	MergeSnapshot(snap2, old, t0.Add(-24*time.Hour))
	p.Snapshot = snap2
	if got := names(SelectBlockers(comps, sigs, p)); !strings.Contains(got, "vmnetbridge") {
		t.Fatalf("start type change not detected: %q", got)
	}

	// Seen only minutes before the block: not trusted yet.
	recent := &ComponentSnapshot{}
	MergeSnapshot(recent, known, t0.Add(-24*time.Hour))
	MergeSnapshot(recent, comps, t0.Add(-10*time.Minute))
	p.Snapshot = recent
	if got := names(SelectBlockers(comps, sigs, p)); !strings.Contains(got, "RfwFilter") {
		t.Fatalf("component seen 10 minutes earlier was trusted: %q", got)
	}
}

func TestSelectBlockersNeverChoosesMicrosoftOrProtected(t *testing.T) {
	comps := []Component{
		{Name: "NewDrv", Kernel: true, Running: true, Start: StartDemand, Changed: t0},
		{Name: "WinSvc", Start: StartAuto, DependsOn: []string{"NewDrv"}},
		{Name: "MyAgent", Start: StartAuto, DependsOn: []string{"NewDrv"}},
	}
	sigs := map[string]Signature{
		"newdrv": {Status: "NotSigned"},
		"winsvc": {Valid: true, Microsoft: true},
	}
	p := BlockerPolicy{KnownGoodBefore: t0, Protected: append([]string{"myagent*"}, DefaultProtectedComponents...)}
	if got := names(SelectBlockers(comps, sigs, p)); got != "NewDrv" {
		t.Fatalf("got %q, want only NewDrv", got)
	}
	if got := SelectBlockers(nil, nil, p); got != nil {
		t.Fatalf("nothing to choose from: %v", got)
	}
}

// When a new driver is found, a new service is disabled only if it starts
// that driver; a new service alone is a suspect only without new drivers.
func TestSelectBlockersPrefersDrivers(t *testing.T) {
	comps := []Component{
		{Name: "NewFilter", Kernel: true, Running: true, Start: StartSystem},
		{Name: "FilterSvc", Start: StartAuto, DependsOn: []string{"NewFilter"}},
		{Name: "GoogleUpdater", Start: StartAuto},
		{Name: "Radmin", Start: StartAuto},
		{Name: "raddrvv3", Kernel: true, Running: true, Start: StartSystem},
	}
	sigs := map[string]Signature{
		"newfilter": {Valid: true, Signer: "Vendor", Status: "Valid"}, "filtersvc": {Valid: true, Status: "Valid"},
		"googleupdater": {Valid: true, Status: "Valid"}, "radmin": {Valid: true, Status: "Valid"}, "raddrvv3": {Valid: true, Status: "Valid"},
	}
	p := BlockerPolicy{Snapshot: &ComponentSnapshot{Components: map[string]SnapshotEntry{}}, KnownGoodBefore: t0, Protected: DefaultProtectedComponents}
	if got := names(SelectBlockers(comps, sigs, p)); got != "FilterSvc,NewFilter" {
		t.Fatalf("got %q, want FilterSvc,NewFilter", got)
	}
	if got := names(SelectBlockers(comps[2:4], sigs, p)); got != "GoogleUpdater" {
		t.Fatalf("without new drivers got %q, want GoogleUpdater", got)
	}
}

func TestMergeSnapshot(t *testing.T) {
	snap := &ComponentSnapshot{}
	now := t0
	if !MergeSnapshot(snap, []Component{{Name: "A", Start: 2, Changed: longAgo}, {Name: "B", Start: 3}}, now) {
		t.Fatal("first snapshot reported no change")
	}
	if !snap.Components["a"].FirstSeen.Equal(longAgo) || !snap.Components["b"].FirstSeen.Equal(now) {
		t.Fatalf("first snapshot times: %+v", snap.Components)
	}
	later := now.Add(time.Hour)
	if MergeSnapshot(snap, []Component{{Name: "A", Start: 2, Changed: longAgo}, {Name: "B", Start: 3}}, later) {
		t.Fatal("unchanged components reported as a change")
	}
	MergeSnapshot(snap, []Component{{Name: "A", Start: StartDisabled}, {Name: "C", Start: 2, Changed: longAgo}}, later)
	if _, ok := snap.Components["b"]; ok {
		t.Fatal("removed component kept")
	}
	if !snap.Components["a"].FirstSeen.Equal(longAgo) {
		t.Fatal("disabling a component made it untrusted")
	}
	if !snap.Components["c"].FirstSeen.Equal(later) {
		t.Fatal("a component added later must count from when it was seen")
	}
}

func TestImageFile(t *testing.T) {
	root := `C:\Windows`
	for _, tc := range []struct{ image, name, want string }{
		{`"C:\Program Files\rfw\rfw-service.exe" run`, "RfwService", `C:\Program Files\rfw\rfw-service.exe`},
		{`C:\Program Files\rfw\rfwfilter.sys`, "RfwFilter", `C:\Program Files\rfw\rfwfilter.sys`},
		{`\SystemRoot\System32\drivers\afd.sys`, "afd", `C:\Windows\System32\drivers\afd.sys`},
		{`System32\drivers\tcpip.sys`, "Tcpip", `C:\Windows\System32\drivers\tcpip.sys`},
		{`%SystemRoot%\system32\svchost.exe -k netsvcs -p`, "x", `C:\Windows\system32\svchost.exe`},
		{`\??\C:\Tools\drv.sys`, "drv", `C:\Tools\drv.sys`},
		{`C:\Windows\System32\OpenSSH\sshd.exe`, "sshd", `C:\Windows\System32\OpenSSH\sshd.exe`},
		{``, "nodrv", `C:\Windows\System32\drivers\nodrv.sys`},
	} {
		kernel := strings.HasSuffix(tc.want, ".sys")
		if got := ImageFile(tc.image, tc.name, kernel, root); got != tc.want {
			t.Errorf("ImageFile(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}
}

func TestIsMicrosoftSigner(t *testing.T) {
	for subject, want := range map[string]bool{
		"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US":                                  true,
		"CN=Microsoft Windows Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US":                        true,
		"CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US": false,
		"CN=Microsoft Windows, O=Evil Corp":                    false,
		"CN=Tailscale Inc., O=Tailscale Inc., L=Toronto, C=CA": false,
		"": false,
	} {
		if got := IsMicrosoftSigner(subject); got != want {
			t.Errorf("IsMicrosoftSigner(%q) = %v", subject, got)
		}
	}
}

func TestSignerName(t *testing.T) {
	if got := SignerName(`CN="Cisco Systems, Inc.", O="Cisco Systems, Inc.", L=San Jose, C=US`); got != "Cisco Systems, Inc." {
		t.Fatalf("quoted CN: %q", got)
	}
	if got := SignerName("CN=Tailscale Inc., O=Tailscale Inc."); got != "Tailscale Inc." {
		t.Fatalf("plain CN: %q", got)
	}
}

func TestParseNetstatListening(t *testing.T) {
	out := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       4120
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1188
  TCP    127.0.0.1:5939         0.0.0.0:0              LISTENING       3012
  TCP    100.117.108.1:5985     0.0.0.0:0              LISTENING       4
  TCP    192.168.1.50:22        100.64.0.7:51234       ESTABLISHED     4120
  TCP    [::]:22                [::]:0                 LISTENING       4120
  TCP    [fe80::1%12]:139       [::]:0                 LISTENING       4
`
	got := ParseNetstatListening(out)
	if strings.Join(got[22], " ") != "0.0.0.0 ::" || got[3389][0] != "0.0.0.0" || got[5939][0] != "127.0.0.1" || got[139][0] != "fe80::1" {
		t.Fatalf("parsed: %v", got)
	}
}

func TestTestLocalAccess(t *testing.T) {
	listening := map[int][]string{22: {"0.0.0.0"}, 3389: {"0.0.0.0"}, 5939: {"127.0.0.1"}}
	var mu sync.Mutex
	var dialed []string
	dial := func(ctx context.Context, addr string) error {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		if strings.HasSuffix(addr, ":22") {
			<-ctx.Done() // held by a filter
			return ctx.Err()
		}
		return nil
	}
	res := TestLocalAccess(context.Background(), "192.168.1.50", []int{22, 3389, 5939, 80}, listening, 50*time.Millisecond, dial)
	if !res.Blocked() || res.Summary() != "22 timeout, 3389 ok" {
		t.Fatalf("result: %+v (%s)", res, res.Summary())
	}
	if len(dialed) != 2 {
		t.Fatalf("dialed ports that do not listen on the address: %v", dialed)
	}
	ok := TestLocalAccess(context.Background(), "192.168.1.50", []int{3389}, listening, time.Second, dial)
	if ok.Blocked() || !ok.Tested() {
		t.Fatalf("working port reported blocked: %+v", ok)
	}
	if none := TestLocalAccess(context.Background(), "", []int{22}, listening, time.Second, dial); none.Tested() {
		t.Fatal("tested without an address")
	}
	refused := TestLocalAccess(context.Background(), "10.0.0.5", []int{22}, listening, time.Second,
		func(context.Context, string) error {
			return errors.New("dial tcp 10.0.0.5:22: connectex: An attempt was made to access a socket in a way forbidden by its access permissions.")
		})
	if !refused.Blocked() || !strings.Contains(refused.Summary(), "forbidden") {
		t.Fatalf("blocked connection not reported: %+v", refused)
	}
}
