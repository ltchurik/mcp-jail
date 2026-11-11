//go:build windows

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// The launcher: runs as `mcp-jail _appcontainer`, the child of the jail,
// with the jail's pipes as its standard handles. It creates (or finds) the
// AppContainer profile, grants the container SID access to the policy's
// directories with icacls, starts the server as a lowbox process that
// inherits those handles, waits for it and removes the grants again.
//
// An AppContainer token passes an access check only when both the user and
// the container (or a capability it holds) are granted, so the user's own
// files stay out of reach unless a directory is listed in the policy;
// Windows and Program Files grant ALL APPLICATION PACKAGES read and execute.
// Without the internetClient capability the process has no network at all.
//
// Everything Win32 is called through syscall.NewLazyDLL: no dependency on
// golang.org/x/sys.

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modUserenv  = syscall.NewLazyDLL("userenv.dll")
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modOle32    = syscall.NewLazyDLL("ole32.dll")

	procCreateAppContainerProfile         = modUserenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile         = modUserenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSid             = modUserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	procGetAppContainerFolderPath         = modUserenv.NewProc("GetAppContainerFolderPath")
	procConvertStringSidToSid             = modAdvapi32.NewProc("ConvertStringSidToSidW")
	procConvertSidToStringSid             = modAdvapi32.NewProc("ConvertSidToStringSidW")
	procFreeSid                           = modAdvapi32.NewProc("FreeSid")
	procLocalFree                         = modKernel32.NewProc("LocalFree")
	procCoTaskMemFree                     = modOle32.NewProc("CoTaskMemFree")
	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = modKernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcessW                    = modKernel32.NewProc("CreateProcessW")
	procCreateJobObjectW                  = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject           = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject          = modKernel32.NewProc("AssignProcessToJobObject")
)

const (
	procThreadAttributeSecurityCapabilities = 0x00020009
	extendedStartupInfoPresent              = 0x00080000
	createUnicodeEnvironment                = 0x00000400
	startfUseStdHandles                     = 0x00000100
	jobObjectExtendedLimitInformation       = 9
	jobObjectLimitKillOnJobClose            = 0x00002000
	seGroupEnabled                          = 0x00000004
	hrAlreadyExists                         = 0x800700B7 // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)

	capInternetClient             = "S-1-15-3-1"
	capPrivateNetworkClientServer = "S-1-15-3-3"
	aclRecord                     = "mcp-jail-acl.json"
)

type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}

type securityCapabilities struct {
	AppContainerSid uintptr
	Capabilities    *sidAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

type startupInfoEx struct {
	syscall.StartupInfo
	AttributeList *byte
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// RunAppContainer starts o.Command inside the AppContainer (or plainly,
// with o.Plain) and returns its exit status.
func RunAppContainer(o AppContainerOptions, logf func(string, ...any)) (int, error) {
	if len(o.Command) == 0 {
		return 2, errors.New("appcontainer: no server command")
	}
	exe, err := exec.LookPath(o.Command[0])
	if err != nil {
		return 2, fmt.Errorf("appcontainer: %w", err)
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return 2, fmt.Errorf("appcontainer: %w", err)
	}
	env := mergeEnv(windowsBaseEnv(), passthroughEnv(o.Env), o.Set)
	// Whatever ends this process ends the server too: the job dies with
	// its last handle, which is ours and stays open until we exit (closing
	// it earlier would kill us as well, we are a member). Best effort: a
	// host that forbids nested jobs still gets the sandbox.
	if _, err := keepTogether(); err != nil {
		logf("appcontainer: job object: %v (the server may outlive the jail)", err)
	}
	if o.Plain {
		return runPlainWindows(exe, o, env)
	}

	sid, sidStr, err := ensureProfile(o.Profile)
	if err != nil {
		return 2, err
	}
	defer func() { _, _, _ = procFreeSid.Call(sid) }()
	folder, err := containerFolder(sidStr)
	if err != nil {
		return 2, err
	}
	home := filepath.Join(folder, "Home")
	for _, d := range []string{filepath.Join(home, "AppData", "Local"), filepath.Join(home, "AppData", "Roaming"), filepath.Join(folder, "Temp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return 2, fmt.Errorf("appcontainer: %w", err)
		}
	}
	// The server's home is the container's folder, which its SID owns: the
	// user's profile does not exist for it. An explicit sandbox.env entry wins.
	env = mergeEnv(env, nil, []string{"USERPROFILE=" + home, "HOME=" + home, "APPDATA=" + filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA=" + filepath.Join(home, "AppData", "Local"), "TEMP=" + filepath.Join(folder, "Temp"), "TMP=" + filepath.Join(folder, "Temp")}, passthroughEnv(o.Env), o.Set)
	cwd := o.Cwd
	if cwd == "" {
		cwd = home
	}

	acl := &aclGrants{sid: sidStr, record: filepath.Join(folder, aclRecord)}
	acl.removeStale(logf)
	for _, d := range o.ReadOnly {
		if err := acl.grant(d, "(OI)(CI)(RX)", false); err != nil {
			acl.removeAll(logf)
			return 2, err
		}
	}
	for _, d := range o.ReadWrite {
		if err := acl.grant(d, "(OI)(CI)(M)", true); err != nil {
			acl.removeAll(logf)
			return 2, err
		}
	}
	for _, p := range o.Deny {
		if err := acl.deny(p); err != nil {
			acl.removeAll(logf)
			return 2, err
		}
	}
	defer acl.removeAll(logf)

	caps, freeCaps, err := capabilities(o.Network)
	if err != nil {
		return 2, err
	}
	defer freeCaps()
	code, err := startLowbox(exe, o.Command, env, cwd, sid, caps)
	if err != nil {
		return 2, err
	}
	return code, nil
}

// keepTogether puts this process in a job that kills every member when the
// job's last handle closes; children (the server) inherit the job.
func keepTogether() (syscall.Handle, error) {
	h, _, e := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return 0, fmt.Errorf("CreateJobObject: %w", e)
	}
	job := syscall.Handle(h)
	info := jobObjectExtendedLimitInfo{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if r, _, e := procSetInformationJobObject.Call(uintptr(job), jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		_ = syscall.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", e)
	}
	self, _ := syscall.GetCurrentProcess()
	if r, _, e := procAssignProcessToJobObject.Call(uintptr(job), uintptr(self)); r == 0 {
		_ = syscall.CloseHandle(job)
		return 0, fmt.Errorf("AssignProcessToJobObject: %w", e)
	}
	return job, nil
}

// runPlainWindows is sandbox.disabled: the scrubbed environment and the
// shared lifetime, nothing else.
func runPlainWindows(exe string, o AppContainerOptions, env []string) (int, error) {
	cmd := exec.Command(exe, o.Command[1:]...)
	cmd.Env = env
	cmd.Dir = o.Cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	default:
		return 2, fmt.Errorf("start %s: %w", exe, err)
	}
}

// ensureProfile creates the AppContainer profile or finds the existing one
// and returns its SID (to be freed with FreeSid) and the SID as text.
func ensureProfile(name string) (uintptr, string, error) {
	name16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, "", err
	}
	desc16, _ := syscall.UTF16PtrFromString("mcp-jail sandbox for " + name)
	var sid uintptr
	hr, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(desc16)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if uint32(hr) == hrAlreadyExists {
		hr, _, _ = procDeriveAppContainerSid.Call(uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(&sid)))
	}
	if uint32(hr) != 0 {
		return 0, "", fmt.Errorf("appcontainer: profile %s: HRESULT 0x%08x", name, uint32(hr))
	}
	var str *uint16
	if r, _, e := procConvertSidToStringSid.Call(sid, uintptr(unsafe.Pointer(&str))); r == 0 {
		_, _, _ = procFreeSid.Call(sid)
		return 0, "", fmt.Errorf("appcontainer: ConvertSidToStringSid: %w", e)
	}
	s := utf16PtrToString(str)
	_, _, _ = procLocalFree.Call(uintptr(unsafe.Pointer(str)))
	return sid, s, nil
}

// deleteProfile removes a profile and its folder (tests).
func deleteProfile(name string) error {
	name16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if hr, _, _ := procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(name16))); uint32(hr) != 0 {
		return fmt.Errorf("DeleteAppContainerProfile: HRESULT 0x%08x", uint32(hr))
	}
	return nil
}

// containerFolder is %LOCALAPPDATA%\Packages\<profile>\AC, owned by the
// container SID.
func containerFolder(sidStr string) (string, error) {
	sid16, err := syscall.UTF16PtrFromString(sidStr)
	if err != nil {
		return "", err
	}
	var path *uint16
	if hr, _, _ := procGetAppContainerFolderPath.Call(uintptr(unsafe.Pointer(sid16)), uintptr(unsafe.Pointer(&path))); uint32(hr) != 0 {
		return "", fmt.Errorf("appcontainer: GetAppContainerFolderPath: HRESULT 0x%08x", uint32(hr))
	}
	s := utf16PtrToString(path)
	_, _, _ = procCoTaskMemFree.Call(uintptr(unsafe.Pointer(path)))
	return s, nil
}

// capabilities builds the SID_AND_ATTRIBUTES array for the network mode.
func capabilities(network string) ([]sidAndAttributes, func(), error) {
	var names []string
	switch network {
	case "none":
	case "all":
		names = []string{capInternetClient, capPrivateNetworkClientServer}
	default:
		return nil, nil, fmt.Errorf("appcontainer: network %q is not none or all", network)
	}
	var caps []sidAndAttributes
	free := func() {
		for _, c := range caps {
			_, _, _ = procLocalFree.Call(c.Sid)
		}
	}
	for _, n := range names {
		s16, _ := syscall.UTF16PtrFromString(n)
		var sid uintptr
		if r, _, e := procConvertStringSidToSid.Call(uintptr(unsafe.Pointer(s16)), uintptr(unsafe.Pointer(&sid))); r == 0 {
			free()
			return nil, nil, fmt.Errorf("appcontainer: capability %s: %w", n, e)
		}
		caps = append(caps, sidAndAttributes{Sid: sid, Attributes: seGroupEnabled})
	}
	return caps, free, nil
}

// startLowbox creates the server process in the AppContainer, with this
// process's standard handles, and waits for it.
func startLowbox(exe string, argv, env []string, cwd string, sid uintptr, caps []sidAndAttributes) (int, error) {
	var size uintptr
	_, _, _ = procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return 0, errors.New("appcontainer: InitializeProcThreadAttributeList: no size")
	}
	list := make([]byte, size)
	if r, _, e := procInitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&list[0])), 1, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
		return 0, fmt.Errorf("appcontainer: InitializeProcThreadAttributeList: %w", e)
	}
	defer func() { _, _, _ = procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&list[0]))) }()
	sc := securityCapabilities{AppContainerSid: sid, CapabilityCount: uint32(len(caps))}
	if len(caps) > 0 {
		sc.Capabilities = &caps[0]
	}
	if r, _, e := procUpdateProcThreadAttribute.Call(uintptr(unsafe.Pointer(&list[0])), 0, procThreadAttributeSecurityCapabilities,
		uintptr(unsafe.Pointer(&sc)), unsafe.Sizeof(sc), 0, 0); r == 0 {
		return 0, fmt.Errorf("appcontainer: UpdateProcThreadAttribute: %w", e)
	}

	for _, h := range []syscall.Handle{syscall.Stdin, syscall.Stdout, syscall.Stderr} {
		if err := syscall.SetHandleInformation(h, syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT); err != nil {
			return 0, fmt.Errorf("appcontainer: inherit std handle: %w", err)
		}
	}
	si := startupInfoEx{AttributeList: &list[0]}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = startfUseStdHandles
	si.StdInput, si.StdOutput, si.StdErr = syscall.Stdin, syscall.Stdout, syscall.Stderr

	parts := make([]string, 0, len(argv))
	parts = append(parts, syscall.EscapeArg(exe))
	for _, a := range argv[1:] {
		parts = append(parts, syscall.EscapeArg(a))
	}
	cmdline, err := syscall.UTF16FromString(strings.Join(parts, " "))
	if err != nil {
		return 0, err
	}
	exe16, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	cwd16, err := syscall.UTF16PtrFromString(cwd)
	if err != nil {
		return 0, err
	}
	block, err := envBlock(env)
	if err != nil {
		return 0, err
	}
	var pi syscall.ProcessInformation
	r, _, e := procCreateProcessW.Call(uintptr(unsafe.Pointer(exe16)), uintptr(unsafe.Pointer(&cmdline[0])), 0, 0, 1,
		extendedStartupInfoPresent|createUnicodeEnvironment, uintptr(unsafe.Pointer(&block[0])), uintptr(unsafe.Pointer(cwd16)),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return 0, fmt.Errorf("appcontainer: start %s: %w", exe, e)
	}
	_ = syscall.CloseHandle(pi.Thread)
	defer func() { _ = syscall.CloseHandle(pi.Process) }()
	if _, err := syscall.WaitForSingleObject(pi.Process, syscall.INFINITE); err != nil {
		return 0, fmt.Errorf("appcontainer: wait: %w", err)
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(pi.Process, &code); err != nil {
		return 0, fmt.Errorf("appcontainer: exit code: %w", err)
	}
	return int(code), nil
}

// aclGrants tracks what icacls granted the container SID, so it can be
// removed again: at exit, and at the next start when the previous run died
// before its cleanup (the record lives in the container's own folder).
type aclGrants struct {
	sid    string
	record string
	Grants []string `json:"grants"`
	Denies []string `json:"denies"`
	// Labels are the read_write directories given a Low integrity label:
	// the container runs at low integrity and could not write to a
	// medium-integrity directory even with the grant. Restored to Medium.
	Labels []string `json:"labels"`
}

func icaclsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "icacls.exe")
}

func (a *aclGrants) icacls(args ...string) error {
	out, err := exec.Command(icaclsPath(), append(args, "/Q")...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s: %s", strings.Join(args, " "), oneLine(string(out), err))
	}
	return nil
}

func (a *aclGrants) save() error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(a.record, b, 0o600)
}

// grant gives the container SID the rights on dir (a directory: inherited
// by everything below it) and records it; a writable directory also gets
// the Low integrity label the container needs to write there.
func (a *aclGrants) grant(dir, rights string, writable bool) error {
	if err := a.icacls(dir, "/grant", "*"+a.sid+":"+rights); err != nil {
		return fmt.Errorf("appcontainer: %w", err)
	}
	a.Grants = append(a.Grants, dir)
	if writable {
		if err := a.icacls(dir, "/setintegritylevel", "(OI)(CI)L"); err != nil {
			return fmt.Errorf("appcontainer: %w", err)
		}
		a.Labels = append(a.Labels, dir)
	}
	return a.save()
}

// deny hides a protected path inside a granted directory: a deny ACE for
// the container SID, which Windows evaluates before any grant.
func (a *aclGrants) deny(path string) error {
	rights := "(F)"
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		rights = "(OI)(CI)(F)"
	}
	if err := a.icacls(path, "/deny", "*"+a.sid+":"+rights); err != nil {
		return fmt.Errorf("appcontainer: %w", err)
	}
	a.Denies = append(a.Denies, path)
	return a.save()
}

// removeAll takes every recorded ACE back and deletes the record.
func (a *aclGrants) removeAll(logf func(string, ...any)) {
	for _, d := range a.Grants {
		if err := a.icacls(d, "/remove:g", "*"+a.sid); err != nil {
			logf("appcontainer: cleanup: %v", err)
		}
	}
	for _, d := range a.Denies {
		if err := a.icacls(d, "/remove:d", "*"+a.sid); err != nil {
			logf("appcontainer: cleanup: %v", err)
		}
	}
	for _, d := range a.Labels {
		if err := a.icacls(d, "/setintegritylevel", "(OI)(CI)M"); err != nil {
			logf("appcontainer: cleanup: %v", err)
		}
	}
	a.Grants, a.Denies, a.Labels = nil, nil, nil
	_ = os.Remove(a.record)
}

// removeStale undoes what a previous run of this profile left behind.
func (a *aclGrants) removeStale(logf func(string, ...any)) {
	b, err := os.ReadFile(a.record)
	if err != nil {
		return
	}
	var old aclGrants
	if json.Unmarshal(b, &old) == nil && (len(old.Grants) > 0 || len(old.Denies) > 0 || len(old.Labels) > 0) {
		logf("appcontainer: removing %d stale grant(s) left by a previous run", len(old.Grants)+len(old.Denies)+len(old.Labels))
		old.sid, old.record = a.sid, a.record
		old.removeAll(logf)
	}
	_ = os.Remove(a.record)
}

// windowsBaseEnv is what every Windows process needs to find the system:
// the counterpart of the base paths a Linux jail sees.
func windowsBaseEnv() []string {
	var out []string
	for _, k := range []string{"SystemRoot", "SystemDrive", "windir", "ComSpec", "PATHEXT", "OS", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PUBLIC", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "ALLUSERSPROFILE"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// mergeEnv combines NAME=value lists; a later list overrides an earlier one
// (names compare case-insensitively, as Windows does), the result is sorted
// the way an environment block must be.
func mergeEnv(lists ...[]string) []string {
	vals := map[string]string{}
	for _, l := range lists {
		for _, kv := range l {
			k, _, _ := strings.Cut(kv, "=")
			vals[strings.ToUpper(k)] = kv
		}
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, vals[k])
	}
	return out
}

// envBlock is the UTF-16 environment block CreateProcess takes.
func envBlock(env []string) ([]uint16, error) {
	var b []uint16
	for _, kv := range env {
		u, err := syscall.UTF16FromString(kv)
		if err != nil {
			return nil, err
		}
		b = append(b, u...)
	}
	return append(b, 0), nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; ptr = unsafe.Add(ptr, 2) {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}
