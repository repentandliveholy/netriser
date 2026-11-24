//go:build windows

package install

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/repentandliveholy/netriser/internal/config"
	"github.com/repentandliveholy/netriser/internal/netengine"
	"github.com/repentandliveholy/netriser/internal/setup"
	"github.com/repentandliveholy/netriser/internal/term"
	"github.com/repentandliveholy/netriser/internal/watchdog"
)

const (
	serviceName = "netriser"
	legacyName  = "mesh-watchdog"
	envKey      = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")
)

// LaunchedByDoubleClick reports whether the program owns its console alone,
// which is the case when Explorer started it (double-click). Started from a
// terminal, the console is shared with the shell.
func LaunchedByDoubleClick() bool {
	var ids [4]uint32
	n, _, _ := kernel32.NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}

// IsAdmin reports whether the process runs with administrator rights.
func IsAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// elevate starts this program again with administrator rights; Windows asks
// the user (UAC).
func elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var quoted []string
	for _, a := range args {
		quoted = append(quoted, windows.EscapeArg(a))
	}
	cwd, _ := os.Getwd()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := windows.UTF16PtrFromString(cwd)
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_NORMAL)
}

func uiLanguage() string {
	r, _, _ := kernel32.NewProc("GetUserDefaultUILanguage").Call()
	return LanguageFromLangID(uint16(r))
}

type layout struct {
	binDir, binPath, licenseDir      string
	legacyDir, legacyPath            string
	newData, legacyData, backupsRoot string
	config, legacyConfig             string
}

func newLayout(confPath string) layout {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	l := layout{
		binDir:      filepath.Join(pf, "NetRiser"),
		legacyDir:   filepath.Join(pf, "mesh-watchdog"),
		newData:     filepath.Join(pd, "netriser"),
		legacyData:  filepath.Join(pd, "mesh-watchdog"),
		backupsRoot: filepath.Join(pd, "NetRiser-Backups"),
	}
	l.binPath = filepath.Join(l.binDir, "netriser.exe")
	l.licenseDir = filepath.Join(l.binDir, "licenses")
	l.legacyPath = filepath.Join(l.legacyDir, "mesh-watchdog.exe")
	l.config = filepath.Join(l.newData, "config.yaml")
	if confPath != "" {
		l.config, _ = filepath.Abs(confPath)
	}
	return l
}

// serviceInfo describes an installed service.
type serviceInfo struct {
	exists, running, auto, disabled bool
	config                          string // --config in its command line
}

var configArg = regexp.MustCompile(`--config(?:=|\s+)(?:"([^"]+)"|(\S+))`)

func queryService(m *mgr.Mgr, name string) serviceInfo {
	s, err := m.OpenService(name)
	if err != nil {
		return serviceInfo{}
	}
	defer s.Close()
	info := serviceInfo{exists: true}
	if st, err := s.Query(); err == nil {
		info.running = st.State != svc.Stopped
	}
	if c, err := s.Config(); err == nil {
		info.auto = c.StartType == mgr.StartAutomatic
		info.disabled = c.StartType == mgr.StartDisabled
		if mm := configArg.FindStringSubmatch(c.BinaryPathName); mm != nil {
			info.config = mm[1] + mm[2]
		}
	}
	return info
}

// installer holds the state needed for rollback.
type installer struct {
	o          Options
	p          *prompter
	l          layout
	m          *mgr.Mgr
	newSvc     serviceInfo
	legacySvc  serviceInfo
	backup     string
	backedUp   []string // paths saved to the backup (existing or not)
	mutating   bool
	pathBefore string
	pathType   uint32
	pathSet    bool
}

// Run installs NetRiser and returns the process exit code.
func Run(o Options) int {
	out := os.Stdout
	p := &prompter{out: out, s: term.For(out), yes: o.Yes, lang: o.Lang}
	if p.lang == "" {
		p.lang = uiLanguage()
	}
	in, _, closeTerminal, ok := setup.Terminal()
	defer closeTerminal()
	if ok {
		p.ok, p.in = true, bufio.NewReader(in)
	}
	if o.DoubleClick {
		defer func() {
			if p.ok {
				fmt.Fprint(out, "\n"+p.t("inst_press_enter"))
				_, _ = p.in.ReadString('\n')
			}
		}()
	}

	if !IsAdmin() {
		if o.DoubleClick {
			args := []string{"install", "--double-click"}
			if o.ConfPath != "" {
				args = append(args, "--config", o.ConfPath)
			}
			if o.Lang != "" {
				args = append(args, "--lang="+o.Lang)
			}
			if err := elevate(args); err != nil {
				p.bad("inst_uac_declined")
				return 1
			}
			p.ok = false // this window closes; the elevated one continues
			return 0
		}
		p.bad("inst_admin_need")
		return 1
	}

	m, err := mgr.Connect()
	if err != nil {
		p.bad("inst_failed", err)
		return 1
	}
	defer m.Disconnect()
	inst := &installer{o: o, p: p, m: m}
	return inst.run()
}

func (in *installer) run() int {
	p, o := in.p, in.o
	in.newSvc = queryService(in.m, serviceName)
	in.legacySvc = queryService(in.m, legacyName)
	confPath := o.ConfPath
	if confPath == "" {
		confPath = in.legacySvc.config
	}
	if confPath == "" {
		confPath = in.newSvc.config
	}
	in.l = newLayout(confPath)
	in.l.legacyConfig = confPath

	p.say(p.s.Title(p.t("inst_title", o.Version)))
	if o.Lang == "" {
		def := ""
		if cur, _, err := setup.Current(in.l.config); err == nil && fileExists(in.l.config) {
			def = setup.EffectiveLanguage(cur)
		}
		if def == "" {
			def = uiLanguage()
		}
		p.lang = p.askLanguage(def)
	}

	p.step("inst_s1")
	existing := fileExists(in.l.config)
	switch {
	case in.newSvc.exists:
		p.say("  " + p.t("inst_existing", in.l.binPath))
	case in.legacySvc.exists:
		p.say("  " + p.t("inst_legacy"))
	}
	p.say("  " + p.t("inst_cfg", in.l.config))

	// Questions first, before anything is stopped or changed.
	rescued, needRestart := in.rescue()
	recommended := true
	if !rescued {
		key := "inst_settings_new_q"
		if existing {
			key = "inst_settings_keep_q"
		}
		recommended = p.ask(p.t(key), true)
	}

	if err := in.apply(recommended); err != nil {
		p.bad("inst_failed", err)
		if in.mutating {
			if rbErr := in.rollback(); rbErr != nil {
				p.bad("inst_rollback_failed", rbErr, in.backup)
			} else {
				p.warn("inst_rolled_back")
			}
		}
		return 1
	}

	p.say("")
	p.good("inst_done")
	p.say(p.s.Dim(p.t("inst_backup_hint", in.backup)))
	p.say("")
	p.say(p.t("inst_cmds"))
	for _, c := range [][2]string{{"nr status", "inst_c_status"}, {"nr logs", "inst_c_logs"}, {"nr blockers", "inst_c_blockers"}, {"nr setup", "inst_c_setup"}} {
		p.say("  " + p.s.Green(fmt.Sprintf("%-14s", c[0])) + " " + p.t(c[1]))
	}
	if needRestart {
		p.say("")
		if p.ask(p.t("inst_restart_q"), true) {
			if err := exec.Command("shutdown.exe", "/r", "/t", "10", "/c", "NetRiser: restart to unload the disabled components").Run(); err == nil {
				p.warn("inst_restarting")
				return 0
			}
		}
		p.warn("inst_restart_later")
	}
	return 0
}

// rescue looks for software that blocks connections on this computer and
// offers to disable it. It reports whether it asked, and whether a restart
// is needed to unload what was disabled.
func (in *installer) rescue() (asked, needRestart bool) {
	p := in.p
	p.step("inst_s2")
	cfg, err := loadConfig(in.l.config)
	if err != nil {
		p.warn("inst_scan_failed", err)
		return false, false
	}
	w := watchdog.NewWatchdog(cfg, false)
	ctx := context.Background()
	scan, err := w.ScanBlockers(ctx)
	switch {
	case scan == nil:
	case !scan.Access.Tested():
		p.say("  " + p.t("inst_access_none"))
	case scan.Access.Blocked():
		p.say("  " + p.s.Red(p.t("inst_access_blocked", scan.Access.Summary())))
	default:
		p.say("  " + p.t("inst_access_ok", scan.Access.Summary()))
	}
	if err != nil {
		p.warn("inst_scan_failed", err)
		return false, false
	}
	// On a computer that accepts its own connections nothing is blocked:
	// recently installed software is not offered for disabling.
	if scan.Access.Tested() && !scan.Access.Blocked() {
		return false, false
	}
	if len(scan.Candidates) == 0 {
		if scan.Access.Blocked() {
			p.warn("inst_not_found")
		}
		return false, false
	}
	p.say("  " + p.t("inst_found"))
	for _, b := range scan.Candidates {
		kind := p.t("inst_kind_svc")
		if b.Kernel {
			kind = p.t("inst_kind_drv")
		}
		p.say(fmt.Sprintf("    %s (%s): %s", p.s.Bold(b.Name), kind, b.Reason))
		if b.Image != "" {
			p.say("      " + p.s.Dim(b.Image))
		}
	}
	if !p.ask(p.t("inst_disable_q"), true) || (!p.ok && !p.yes) {
		p.warn("inst_skip_disable")
		return true, false
	}
	if err := cfg.EnsureDirectories(); err != nil {
		p.warn("inst_scan_failed", err)
		return true, false
	}
	stuck := false
	for _, a := range w.DisableBlockers(ctx, scan.Candidates) {
		p.say("    " + a.String())
		if a.Status == netengine.ActionPartial {
			stuck = true
		}
	}
	time.Sleep(3 * time.Second)
	after, _ := w.ScanBlockers(ctx)
	if after != nil && after.Access.Tested() && !after.Access.Blocked() && !stuck {
		p.good("inst_disabled_ok", after.Access.Summary())
		return true, false
	}
	p.warn("inst_disabled_restart")
	return true, true
}

func loadConfig(path string) (*config.Config, error) {
	if fileExists(path) {
		return config.Load(path)
	}
	return config.Load("")
}

// apply performs the installation; on error the caller rolls back.
func (in *installer) apply(recommended bool) error {
	p, l := in.p, in.l

	in.backup = filepath.Join(l.backupsRoot, "migration-"+time.Now().UTC().Format("20060102T150405Z")+"-"+randomHex())
	p.step("inst_s3", in.backup)
	if err := os.MkdirAll(in.backup, 0o700); err != nil {
		return err
	}
	for _, path := range []string{l.licenseDir, l.binPath, filepath.Join(l.binDir, "nr.cmd"), filepath.Join(l.binDir, "mesh-watchdog.cmd"), l.legacyPath, l.newData, l.legacyData, l.legacyConfig} {
		if path == "" {
			continue
		}
		in.backedUp = append(in.backedUp, path)
		if err := copyPath(path, in.saved(path)); err != nil {
			return fmt.Errorf("backup of %s: %w", path, err)
		}
	}
	for name, info := range map[string]serviceInfo{serviceName: in.newSvc, legacyName: in.legacySvc} {
		if info.exists {
			_ = exec.Command("reg.exe", "export", `HKLM\SYSTEM\CurrentControlSet\Services\`+name, filepath.Join(in.backup, name+"-service.reg"), "/y").Run()
		}
	}

	p.step("inst_s4", l.binPath)
	in.mutating = true
	if err := os.MkdirAll(l.binDir, 0o755); err != nil {
		return err
	}
	if in.newSvc.running {
		if err := stopService(in.m, serviceName); err != nil {
			return err
		}
	}
	if in.legacySvc.running {
		if err := stopService(in.m, legacyName); err != nil {
			return err
		}
	}
	if in.legacySvc.exists {
		if err := setStartType(in.m, legacyName, mgr.StartDisabled); err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !samePath(self, l.binPath) {
		stage := filepath.Join(l.binDir, ".netriser-"+randomHex()+".new")
		if err := copyFile(self, stage); err != nil {
			os.Remove(stage)
			return fmt.Errorf("copy the program: %w", err)
		}
		if err := os.Rename(stage, l.binPath); err != nil {
			os.Remove(stage)
			return fmt.Errorf("replace %s: %w", l.binPath, err)
		}
	}
	if err := os.MkdirAll(l.licenseDir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"LICENSE", "THIRD_PARTY_NOTICES"} {
		data, _ := Legal.ReadFile("legal/" + name)
		if err := os.WriteFile(filepath.Join(l.licenseDir, name), data, 0o644); err != nil {
			return err
		}
	}
	if err := in.runInstalled("migrate"); err != nil {
		return fmt.Errorf("move legacy files: %w", err)
	}

	p.step("inst_s5", l.config)
	args := []string{"--config", l.config, "setup", "--lang=" + p.lang, "--no-restart"}
	if recommended || !p.ok {
		args = append(args, "--non-interactive")
	}
	if err := in.runProgram(args...); err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	p.step("inst_s6")
	if in.newSvc.exists {
		if err := startService(in.m, serviceName); err != nil {
			return err
		}
	} else if err := in.runInstalled("service", "install"); err != nil {
		return fmt.Errorf("service install: %w", err)
	}
	if !waitRunning(in.m, serviceName, 20*time.Second) {
		return errors.New("the netriser service is not running")
	}
	for _, name := range []string{"nr.cmd", "mesh-watchdog.cmd"} {
		if err := os.WriteFile(filepath.Join(l.binDir, name), []byte(commandWrapper), 0o644); err != nil {
			return err
		}
	}
	if err := in.addBinDirToPath(); err != nil {
		return fmt.Errorf("PATH: %w", err)
	}
	if in.legacySvc.exists {
		if err := deleteService(in.m, legacyName); err != nil {
			return fmt.Errorf("remove the mesh-watchdog service: %w", err)
		}
	}
	return nil
}

// runInstalled runs the installed program with the configuration the
// existing service used (if any).
func (in *installer) runInstalled(args ...string) error {
	if in.l.legacyConfig != "" {
		args = append([]string{"--config", in.l.legacyConfig}, args...)
	}
	return in.runProgram(args...)
}

func (in *installer) runProgram(args ...string) error {
	cmd := exec.Command(in.l.binPath, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func (in *installer) saved(path string) string {
	rel := path
	if vol := filepath.VolumeName(path); vol != "" {
		rel = strings.TrimPrefix(path[len(vol):], `\`)
	}
	return filepath.Join(in.backup, "files", rel)
}

// rollback restores the files and services saved before the change.
func (in *installer) rollback() error {
	var errs []string
	_ = stopService(in.m, serviceName)
	if !in.newSvc.exists {
		_ = deleteService(in.m, serviceName)
	}
	for _, path := range in.backedUp {
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
			continue
		}
		if err := copyPath(in.saved(path), path); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if in.newSvc.exists && in.newSvc.running {
		_ = startService(in.m, serviceName)
	}
	if in.legacySvc.exists {
		st := mgr.StartManual
		switch {
		case in.legacySvc.auto:
			st = mgr.StartAutomatic
		case in.legacySvc.disabled:
			st = mgr.StartDisabled
		}
		_ = setStartType(in.m, legacyName, uint32(st))
		if in.legacySvc.running {
			_ = startService(in.m, legacyName)
		}
	}
	if in.pathSet {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.SET_VALUE); err == nil {
			if in.pathType == registry.EXPAND_SZ {
				_ = k.SetExpandStringValue("Path", in.pathBefore)
			} else {
				_ = k.SetStringValue("Path", in.pathBefore)
			}
			k.Close()
			broadcastEnvironment()
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// addBinDirToPath adds the program folder to the machine PATH.
func (in *installer) addBinDirToPath() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, typ, err := k.GetStringValue("Path")
	if err != nil && err != registry.ErrNotExist {
		return err
	}
	next, changed := AddToPath(cur, in.l.binDir)
	if !changed {
		return nil
	}
	in.pathBefore, in.pathType = cur, typ
	if typ == registry.SZ {
		err = k.SetStringValue("Path", next)
	} else {
		err = k.SetExpandStringValue("Path", next)
	}
	if err != nil {
		return err
	}
	in.pathSet = true
	broadcastEnvironment()
	return nil
}

// broadcastEnvironment tells running programs (Explorer) that the
// environment changed, so new terminals see the PATH.
func broadcastEnvironment() {
	env, _ := windows.UTF16PtrFromString("Environment")
	var result uintptr
	user32.NewProc("SendMessageTimeoutW").Call(0xffff, 0x1A, 0, uintptr(unsafe.Pointer(env)), 0x2, 5000, uintptr(unsafe.Pointer(&result)))
}

func stopService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return err
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop %s: %w", name, err)
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		if st, err = s.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
	}
	return fmt.Errorf("the %s service did not stop", name)
}

func startService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	return nil
}

func waitRunning(m *mgr.Mgr, name string, timeout time.Duration) bool {
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	defer s.Close()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			return true
		}
	}
	return false
}

func setStartType(m *mgr.Mgr, name string, start uint32) error {
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return err
	}
	c.StartType = start
	return s.UpdateConfig(c)
}

func deleteService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	defer s.Close()
	return s.Delete()
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func samePath(a, b string) bool {
	a, _ = filepath.Abs(a)
	b, _ = filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func randomHex() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// copyPath copies a file or a directory tree; a missing source is not an
// error (there is nothing to save or restore).
func copyPath(src, dst string) error {
	st, err := os.Stat(src)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return copyFile(src, dst)
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		// Lock files of a running service cannot be read; they are recreated.
		if strings.HasSuffix(strings.ToLower(path), ".lock") {
			return nil
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
