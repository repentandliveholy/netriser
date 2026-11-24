//go:build windows

// Command nr-sim-block simulates a firewall driver that cuts a Windows host
// off, as an RFW test build did on WS-OVS-010: while it runs, new incoming
// TCP connections to the chosen local port are blocked by a Windows
// Filtering Platform filter, also when the host connects to itself.
//
// The filter lives in a dynamic WFP session: Windows removes it as soon as the
// process ends, however it ends. As a service it ignores stop requests (like
// a hung service), so recovery has to end its process. It exits by itself
// after -max (default 15 minutes).
//
//	nr-sim-block check  [-port 3389]   add the filter for 3 seconds, test, exit
//	nr-sim-block run    [-port 3389]   block until -max, in the console
//	(service)                          started by the service manager
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var (
	fwpuclnt          = windows.NewLazySystemDLL("fwpuclnt.dll")
	procEngineOpen    = fwpuclnt.NewProc("FwpmEngineOpen0")
	procEngineClose   = fwpuclnt.NewProc("FwpmEngineClose0")
	procFilterAdd     = fwpuclnt.NewProc("FwpmFilterAdd0")
	layerRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	condLocalPort     = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
)

const (
	sessionFlagDynamic = 0x1
	rpcAuthnWinNT      = 10
	fwpUint16          = 2
	fwpMatchEqual      = 0
	fwpActionBlock     = 0x1 | 0x1000 // FWP_ACTION_BLOCK | FWP_ACTION_FLAG_TERMINATING
)

// fwpmSession0 is FWPM_SESSION0 (amd64 layout).
type fwpmSession0 struct {
	SessionKey windows.GUID
	Name, Desc *uint16
	Flags      uint32
	TxnWaitMs  uint32
	ProcessID  uint32
	_          uint32
	Sid        uintptr
	Username   *uint16
	KernelMode int32
	_          uint32
}

// fwpmFilterCondition0 is FWPM_FILTER_CONDITION0.
type fwpmFilterCondition0 struct {
	FieldKey  windows.GUID
	MatchType uint32
	_         uint32
	ValueType uint32
	_         uint32
	Value     uintptr
}

// fwpmFilter0 is FWPM_FILTER0 (amd64 layout, 200 bytes).
type fwpmFilter0 struct {
	FilterKey        windows.GUID
	Name, Desc       *uint16
	Flags            uint32
	ProviderKey      *windows.GUID
	ProviderDataSize uint32
	ProviderData     *byte
	LayerKey         windows.GUID
	SubLayerKey      windows.GUID
	WeightType       uint32
	WeightValue      uintptr
	NumConditions    uint32
	Conditions       *fwpmFilterCondition0
	ActionType       uint32
	ActionKey        windows.GUID
	RawContext       uint64
	_                [8]byte
	Reserved         *windows.GUID
	FilterID         uint64
	EffWeightType    uint32
	EffWeightValue   uintptr
}

var logFile = filepath.Join(os.Getenv("ProgramData"), "nr-sim", "nr-sim-block.log")

func logf(format string, args ...any) {
	line := time.Now().Format("2006-01-02 15:04:05 ") + fmt.Sprintf(format, args...)
	fmt.Println(line)
	_ = os.MkdirAll(filepath.Dir(logFile), 0o755)
	if f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintln(f, line)
		f.Close()
	}
}

// block opens a dynamic WFP session and blocks incoming TCP connections to
// port. Closing the returned handle (or the process ending) removes it.
func block(port uint16) (uintptr, uint64, error) {
	if unsafe.Sizeof(fwpmFilter0{}) != 200 || unsafe.Sizeof(fwpmFilterCondition0{}) != 40 || unsafe.Sizeof(fwpmSession0{}) != 72 {
		return 0, 0, fmt.Errorf("unexpected structure layout")
	}
	name, _ := windows.UTF16PtrFromString("NetRiser simulation: block port " + strconv.Itoa(int(port)))
	session := fwpmSession0{Name: name, Flags: sessionFlagDynamic}
	var engine uintptr
	if r, _, _ := procEngineOpen.Call(0, rpcAuthnWinNT, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine))); r != 0 {
		return 0, 0, fmt.Errorf("FwpmEngineOpen0: 0x%x", r)
	}
	cond := fwpmFilterCondition0{FieldKey: condLocalPort, MatchType: fwpMatchEqual, ValueType: fwpUint16, Value: uintptr(port)}
	filter := fwpmFilter0{Name: name, LayerKey: layerRecvAcceptV4, NumConditions: 1, Conditions: &cond, ActionType: fwpActionBlock}
	var id uint64
	if r, _, _ := procFilterAdd.Call(engine, uintptr(unsafe.Pointer(&filter)), 0, uintptr(unsafe.Pointer(&id))); r != 0 {
		procEngineClose.Call(engine)
		return 0, 0, fmt.Errorf("FwpmFilterAdd0: 0x%x", r)
	}
	return engine, id, nil
}

func selfConnect(port uint16) string {
	ip := "127.0.0.1"
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				ip = n.IP.String()
				break
			}
		}
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(int(port))), 3*time.Second)
	if err != nil {
		return ip + ": " + err.Error()
	}
	c.Close()
	return ip + ": connected"
}

type service struct {
	port uint16
	max  time.Duration
}

func (s service) Execute(args []string, r <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	engine, id, err := block(s.port)
	if err != nil {
		logf("service: %v", err)
		return true, 1
	}
	logf("service: blocking incoming TCP port %d (filter %d) for at most %s; stop requests are ignored", s.port, id, s.max)
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}
	deadline := time.After(s.max)
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				logf("service: stop request ignored (simulating a hung service)")
			}
		case <-deadline:
			procEngineClose.Call(engine)
			logf("service: -max reached; filter removed, exiting")
			st <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

func main() {
	port := flag.Int("port", 3389, "local TCP port to block")
	max := flag.Duration("max", 15*time.Minute, "exit after this long")
	if isService, _ := svc.IsWindowsService(); isService {
		flag.CommandLine.Parse(os.Args[1:])
		_ = svc.Run("NrSimBlock", service{port: uint16(*port), max: *max})
		return
	}
	if len(os.Args) < 2 {
		fmt.Println("usage: nr-sim-block check|run [-port 3389] [-max 15m]")
		os.Exit(2)
	}
	mode := os.Args[1]
	flag.CommandLine.Parse(os.Args[2:])
	fmt.Println("before:", selfConnect(uint16(*port)))
	engine, id, err := block(uint16(*port))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("filter %d added on port %d\n", id, *port)
	if mode == "check" {
		fmt.Println("during:", selfConnect(uint16(*port)))
		procEngineClose.Call(engine)
		time.Sleep(500 * time.Millisecond)
		fmt.Println("after:", selfConnect(uint16(*port)))
		return
	}
	time.Sleep(*max)
	procEngineClose.Call(engine)
}
