//go:build windows

package netengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const servicesKey = `SYSTEM\CurrentControlSet\Services`

// Service types (the Type value of a Windows service key).
const (
	typeKernelDriver = 0x1
	typeFSDriver     = 0x2
	typeOwnProcess   = 0x10
	typeShareProcess = 0x20
	typeUserService  = 0x40
)

// ListeningPorts reads the listening TCP sockets from netstat.
func (e *WindowsEngine) ListeningPorts(ctx context.Context) (map[int][]string, error) {
	out, err := e.runCmd(ctx, 15*time.Second, "netstat.exe", "-ano", "-p", "TCP")
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}
	res := ParseNetstatListening(out)
	if out6, err := e.runCmd(ctx, 15*time.Second, "netstat.exe", "-ano", "-p", "TCPv6"); err == nil {
		for port, addrs := range ParseNetstatListening(out6) {
			res[port] = append(res[port], addrs...)
		}
	}
	return res, nil
}

// Components reads the service and driver entries from the registry.
func (e *WindowsEngine) Components(ctx context.Context) ([]Component, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("open services key: %w", err)
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	active, err := activeServices()
	if err != nil {
		return nil, fmt.Errorf("list running services: %w", err)
	}
	var out []Component
	for _, name := range names {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if c, ok := readComponent(root, name); ok {
			c.Running = active[strings.ToLower(name)]
			out = append(out, c)
		}
	}
	return out, nil
}

// activeServices returns the services and drivers that are running or
// starting (lower-case names).
func activeServices() (map[string]bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	var needed, returned uint32
	var buf []byte
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err = windows.EnumServicesStatusEx(m.Handle, windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32|windows.SERVICE_DRIVER, windows.SERVICE_ACTIVE,
			p, uint32(len(buf)), &needed, &returned, nil, nil)
		if err == nil {
			break
		}
		if err != syscall.ERROR_MORE_DATA || needed <= uint32(len(buf)) {
			return nil, err
		}
		buf = make([]byte, needed)
	}
	res := map[string]bool{}
	if returned == 0 {
		return res, nil
	}
	for _, st := range unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), int(returned)) {
		res[strings.ToLower(windows.UTF16PtrToString(st.ServiceName))] = true
	}
	return res, nil
}

func readComponent(root registry.Key, name string) (Component, bool) {
	k, err := registry.OpenKey(root, name, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return Component{}, false
	}
	defer k.Close()
	typ, _, err := k.GetIntegerValue("Type")
	if err != nil || typ&typeUserService != 0 {
		return Component{}, false
	}
	kernel := typ&(typeKernelDriver|typeFSDriver) != 0
	if !kernel && typ&(typeOwnProcess|typeShareProcess) == 0 {
		return Component{}, false
	}
	start, _, err := k.GetIntegerValue("Start")
	if err != nil {
		return Component{}, false
	}
	c := Component{Name: name, Kernel: kernel, Start: int(start), Shared: !kernel && typ&typeShareProcess != 0}
	c.Image, _, _ = k.GetStringValue("ImagePath")
	c.DependsOn, _, _ = k.GetStringsValue("DependOnService")
	// Windows records the driver packages (.inf) a service was installed
	// from; services created directly (sc create) have none.
	owners, _, _ := k.GetStringsValue("Owners")
	c.Package = len(owners) > 0
	if info, err := k.Stat(); err == nil {
		c.Changed = info.ModTime()
	}
	c.Device = boundToDevice(k)
	return c, true
}

// boundToDevice reports whether a driver serves a hardware device. Drivers
// started as legacy (non-Plug and Play) services get a Root\LEGACY_ entry,
// which is not a device.
func boundToDevice(k registry.Key) bool {
	enum, err := registry.OpenKey(k, "Enum", registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer enum.Close()
	count, _, err := enum.GetIntegerValue("Count")
	if err != nil || count == 0 {
		return false
	}
	for i := uint64(0); i < count; i++ {
		id, _, err := enum.GetStringValue(fmt.Sprint(i))
		if err == nil && !strings.HasPrefix(strings.ToUpper(id), `ROOT\LEGACY_`) {
			return true
		}
	}
	return false
}

// Signatures checks image files with Get-AuthenticodeSignature, which also
// covers catalog-signed Windows files.
func (e *WindowsEngine) Signatures(ctx context.Context, comps []Component) (map[string]Signature, error) {
	res := map[string]Signature{}
	if len(comps) == 0 {
		return res, nil
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	type item struct{ Name, Path string }
	var items []item
	for _, c := range comps {
		items = append(items, item{Name: strings.ToLower(c.Name), Path: ImageFileFor(c, root)})
	}
	data, _ := json.Marshal(items)
	script := `$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$items=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('` + base64.StdEncoding.EncodeToString(data) + `'))|ConvertFrom-Json
$out=foreach($i in $items){
  $st='Missing';$sub=''
  if($i.Path -and (Test-Path -LiteralPath $i.Path -PathType Leaf)){
    $s=Get-AuthenticodeSignature -LiteralPath $i.Path
    if($s){$st=[string]$s.Status;if($s.SignerCertificate){$sub=$s.SignerCertificate.Subject}}
  }
  [pscustomobject]@{Name=$i.Name;Status=$st;Subject=$sub}
}
ConvertTo-Json -Compress -InputObject @($out)`
	timeout := 60*time.Second + time.Duration(len(items))*time.Second
	out, err := e.runPowerShell(ctx, timeout, script)
	if err != nil {
		return nil, fmt.Errorf("signature check: %w: %s", err, commandDetail(out))
	}
	var rows []struct{ Name, Status, Subject string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rows); err != nil {
		return nil, fmt.Errorf("signature check output: %w", err)
	}
	for _, r := range rows {
		valid := r.Status == "Valid"
		res[r.Name] = Signature{Valid: valid, Microsoft: valid && IsMicrosoftSigner(r.Subject), Signer: SignerName(r.Subject), Status: r.Status}
	}
	return res, nil
}

// DisableComponent sets Start=4 in the registry (read at the next start of
// Windows), then stops the component. A user-mode service that does not stop
// within 15 seconds has its process ended; a driver that cannot be unloaded
// stays loaded until the next restart.
func (e *WindowsEngine) DisableComponent(ctx context.Context, c Component) ActionResult {
	act := ActionResult{Type: ActionDisableComponent, Target: c.Name, Status: ActionExecuted}
	if err := setStart(c.Name, StartDisabled); err != nil {
		act.Status, act.Error = ActionFailed, err.Error()
		act.Description = "Could not disable " + c.Name
		return act
	}
	stopped, how := stopComponent(ctx, c)
	if stopped {
		act.Description = fmt.Sprintf("Disabled %s (was %s) and %s", c.Name, StartName(c.Start), how)
	} else {
		act.Status = ActionPartial
		act.Description = fmt.Sprintf("Disabled %s (was %s); %s, it stays loaded until the next restart", c.Name, StartName(c.Start), how)
	}
	return act
}

// RestoreComponent sets the start type back.
func (e *WindowsEngine) RestoreComponent(ctx context.Context, name string, start int) ActionResult {
	act := ActionResult{Type: ActionRestoreComponent, Target: name, Status: ActionExecuted,
		Description: fmt.Sprintf("Restored start type of %s to %s", name, StartName(start))}
	if err := setStart(name, start); err != nil {
		act.Status, act.Error = ActionFailed, err.Error()
		act.Description = "Could not restore " + name
	}
	return act
}

func setStart(name string, start int) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey+`\`+name, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer k.Close()
	return k.SetDWordValue("Start", uint32(start))
}

func stopComponent(ctx context.Context, c Component) (bool, string) {
	m, err := mgr.Connect()
	if err != nil {
		return false, "the service manager is not available: " + err.Error()
	}
	defer m.Disconnect()
	s, err := openService(m, c.Name)
	if err != nil {
		return false, "it could not be opened: " + err.Error()
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, "its state is unknown: " + err.Error()
	}
	if st.State == svc.Stopped {
		return true, "it was not running"
	}
	// A hung service may refuse the request; its process is ended below.
	_, _ = s.Control(svc.Stop)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if st, err = s.Query(); err == nil && st.State == svc.Stopped {
			return true, "stopped it"
		}
		time.Sleep(500 * time.Millisecond)
	}
	if c.Kernel {
		return false, "the driver did not unload"
	}
	if c.Shared || st.ProcessId == 0 {
		return false, "it did not stop"
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, st.ProcessId)
	if err != nil {
		return false, "its process could not be opened: " + err.Error()
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return false, "its process could not be ended: " + err.Error()
	}
	_, _ = windows.WaitForSingleObject(h, 5000)
	return true, fmt.Sprintf("ended its process (PID %d) after it did not stop", st.ProcessId)
}

// openService opens a service or driver with the rights needed to stop it
// and to read its process ID. mgr.OpenService asks for all access, which
// some protected services refuse.
func openService(m *mgr.Mgr, name string) (*mgr.Service, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, p, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}
