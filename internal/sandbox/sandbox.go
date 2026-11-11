// Package sandbox builds the command line that launches the MCP server
// inside an isolated environment.
//
// Linux: bubblewrap (bwrap) — user, mount, PID and (optionally) network
// namespaces, with only the paths from the policy visible.
// macOS: sandbox-exec with a generated profile — home directory hidden
// except for the policy's paths, writes only where allowed, network per
// network.mode (allowlist = loopback proxy port only).
// Any host with docker or podman (sandbox.backend docker): a container from
// an image, the policy's paths bind-mounted, see docker.go.
// Other platforms: no isolation; mcp-jail still enforces tool policy, the
// rug-pull lock and audit logging, and prints a warning.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

// Spec is what the launcher needs beyond the policy.
type Spec struct {
	Command []string          // server command and args
	Env     map[string]string // extra env (e.g. HTTP_PROXY)
	Egress  *Egress           // hard egress allowlist (Linux, network.mode allowlist)
	// WorkDir is a private, per-run directory for generated files (macOS
	// profile, private tmp). The caller removes it after the server exits.
	WorkDir string
	// ProxyPort is the loopback port of the cooperative HTTP proxy; macOS
	// lets the jail reach only that port in allowlist mode.
	ProxyPort int
	// Protect lists host paths the jailed server must never see even when a
	// bind would otherwise expose them: the policy file, the audit log, the
	// lock/registry directories with the control socket. Directories and
	// files; missing entries are ignored.
	Protect []string
}

// Egress describes the relay the in-jail shim connects to. See package egress.
type Egress struct {
	Dir        string   // host directory holding egress.sock and resolv.conf
	Exe        string   // mcp-jail binary, re-executed inside the jail as the shim
	Allow      []string // network.allow
	UID, GID   int      // ids the server runs as inside the jail
	ResolvConf string   // file to mount as /etc/resolv.conf
}

// Paths inside the jail.
const (
	jailRunDir = "/run/mcp-jail"
	jailExe    = "/opt/mcp-jail/mcp-jail"
	// ShimCommand is the hidden subcommand the shim is started with.
	ShimCommand = "_egress-shim"
)

// HardEgress reports whether this run enforces network.allow in the kernel
// (Linux with the sandbox on, bwrap or docker) rather than through a
// cooperative HTTP_PROXY.
func HardEgress(p *policy.Policy) bool {
	return runtime.GOOS == "linux" && !p.Sandbox.Disabled && p.Network.Mode == policy.NetAllowlist &&
		p.Sandbox.Backend != policy.BackendSandboxExec
}

// Build returns an exec.Cmd for the jailed server and a description of the
// isolation that was applied (for the log line).
func Build(p *policy.Policy, s Spec) (*exec.Cmd, string, error) {
	argv, how, dir, err := build(p, s)
	if err != nil {
		return nil, "", err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir // "" keeps the current directory
	return cmd, how, nil
}

// build is Build without the exec.Cmd, for tests.
func build(p *policy.Policy, s Spec) (argv []string, how, dir string, err error) {
	if len(s.Command) == 0 {
		return nil, "", "", fmt.Errorf("no server command given (use: mcp-jail run --policy p.yml -- <cmd> [args])")
	}
	env := passthroughEnv(p.Sandbox.Env)
	for k, v := range s.Env {
		env = append(env, k+"="+v)
	}

	if p.Sandbox.Disabled {
		if len(p.Exec.Allow) > 0 {
			return nil, "", "", fmt.Errorf("exec.allow cannot be enforced with sandbox.disabled")
		}
		if runtime.GOOS == "windows" { // no `env -i` there
			return buildWindowsPlain(p, s, "sandbox disabled by policy")
		}
		return append([]string{"env", "-i"}, append(env, s.Command...)...), "sandbox disabled by policy", "", nil
	}
	if err := checkExec(p); err != nil {
		return nil, "", "", err
	}
	switch p.Sandbox.Backend {
	case policy.BackendDocker:
		return buildDocker(p, s, env)
	case policy.BackendBwrap:
		if runtime.GOOS != "linux" {
			return nil, "", "", fmt.Errorf("sandbox.backend bwrap needs Linux (this is %s); use auto or docker", runtime.GOOS)
		}
		return buildLinux(p, s, env)
	case policy.BackendSandboxExec:
		if runtime.GOOS != "darwin" {
			return nil, "", "", fmt.Errorf("sandbox.backend sandbox-exec needs macOS (this is %s); use auto or docker", runtime.GOOS)
		}
		return buildDarwin(p, s, env)
	case policy.BackendAppContainer:
		if runtime.GOOS != "windows" {
			return nil, "", "", fmt.Errorf("sandbox.backend appcontainer needs Windows (this is %s); use auto or docker", runtime.GOOS)
		}
		return buildWindows(p, s)
	}
	switch runtime.GOOS {
	case "linux":
		return buildLinux(p, s, env)
	case "darwin":
		return buildDarwin(p, s, env)
	case "windows":
		return buildWindows(p, s)
	}
	if len(p.Exec.Allow) > 0 {
		return nil, "", "", fmt.Errorf("exec.allow cannot be enforced on %s (no sandbox)", runtime.GOOS)
	}
	why := "no sandbox on " + runtime.GOOS + " (policy/lock/audit only; sandbox.backend: docker would isolate it)"
	return append([]string{"env", "-i"}, append(env, s.Command...)...), why, "", nil
}

func buildLinux(p *policy.Policy, s Spec, env []string) ([]string, string, string, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, "", "", fmt.Errorf("bwrap not found; install bubblewrap or set sandbox.disabled: true")
	}

	hard := p.Network.Mode == policy.NetAllowlist
	if hard && s.Egress == nil {
		// Fail closed: never fall back to the cooperative proxy on Linux.
		return nil, "", "", fmt.Errorf("network.mode=allowlist needs the egress relay; refusing to start without it")
	}
	var args []string
	if hard {
		// The shim must bind :53/:80/:443 inside the jail's network namespace.
		// Only root of the user namespace that owns the netns may do that, so
		// the jail's root is us. The shim then starts the server in a nested
		// user namespace mapped back to our ids; mapping root to a non-root id
		// needs CAP_SETFCAP since Linux 5.12.
		args = append(args, "--unshare-user", "--uid", "0", "--gid", "0",
			"--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "CAP_SETFCAP")
	} else {
		args = append(args, "--unshare-user-try")
	}
	args = append(args,
		"--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--die-with-parent", "--new-session",
		"--proc", "/proc", "--dev", "/dev",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/sbin", "/sbin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl",
		"--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
		"--ro-bind-try", "/etc/hosts", "/etc/hosts",
		"--ro-bind-try", "/etc/passwd", "/etc/passwd",
		"--ro-bind-try", "/etc/group", "/etc/group",
		"--ro-bind-try", "/etc/localtime", "/etc/localtime",
		"--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
	)
	switch {
	case hard:
		args = append(args, "--unshare-net",
			"--ro-bind", s.Egress.ResolvConf, "/etc/resolv.conf",
			"--bind", s.Egress.Dir, jailRunDir,
			"--ro-bind", s.Egress.Exe, jailExe)
	case p.Network.Mode == policy.NetNone:
		args = append(args, "--unshare-net", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf")
	default:
		args = append(args, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf")
	}
	if p.Filesystem.Tmp {
		args = append(args, "--tmpfs", "/tmp")
	}
	for _, d := range p.Filesystem.ReadOnly {
		args = append(args, "--ro-bind", d, d)
	}
	for _, d := range p.Filesystem.ReadWrite {
		args = append(args, "--bind", d, d)
	}
	// The server binary often lives outside /usr (nvm, pyenv, ~/.local, a
	// venv). Bind its toolchain prefix read-only so it can start at all.
	var notes []string
	bound := append(append([]string{}, p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...)
	if prefix, note := toolchainBind(s.Command[0], s.Protect); prefix != "" && !covered(prefix, p) {
		args = append(args, "--ro-bind", prefix, prefix)
		bound = append(bound, prefix)
	} else if note != "" {
		notes = append(notes, note)
	}
	// Same for the working directory (relative script paths, package.json),
	// unless sharing it would expose the home directory or our own state.
	if cwd, err := os.Getwd(); err == nil && !covered(cwd, p) {
		if why := tooBroad(cwd, s.Protect); why == "" {
			args = append(args, "--ro-bind", cwd, cwd, "--chdir", cwd)
			bound = append(bound, cwd)
		} else {
			args = append(args, "--chdir", "/")
			notes = append(notes, "cwd not shared ("+why+")")
		}
	}
	// Mask our own state wherever a bind would expose it.
	for _, m := range masks(s.Protect, bound) {
		if m.dir {
			args = append(args, "--tmpfs", m.path)
		} else {
			args = append(args, "--ro-bind", "/dev/null", m.path)
		}
	}
	// Pinned executables: each file on its own, so its siblings stay absent.
	for _, path := range p.Exec.Allow {
		if dir := coveredBy(path, bound); dir != "" {
			notes = append(notes, "exec.allow "+path+" is inside "+dir+", which is bound whole: its siblings are executable too")
			continue
		}
		args = append(args, "--ro-bind", path, path)
	}
	args = append(args, "--clearenv")
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		args = append(args, "--setenv", k, v)
	}
	args = append(args, "--")
	if hard {
		args = append(args, jailExe, ShimCommand,
			"--socket", jailRunDir+"/egress.sock",
			"--allow", strings.Join(s.Egress.Allow, ","),
			"--uid", strconv.Itoa(s.Egress.UID), "--gid", strconv.Itoa(s.Egress.GID), "--")
	}
	args = append(args, s.Command...)

	why := "bwrap: user/pid/ipc/uts ns"
	switch {
	case hard:
		why += ", net ns + egress allowlist (hard)"
	case p.Network.Mode == policy.NetNone:
		why += ", net ns (no network)"
	}
	if n := len(p.Exec.Allow); n > 0 {
		why += fmt.Sprintf(", %d exec pin(s)", n)
	}
	if len(notes) > 0 {
		why += "; " + strings.Join(notes, "; ")
	}
	return append([]string{bwrap}, args...), why, "", nil
}

// coveredBy returns the bound directory that contains path, or "".
func coveredBy(path string, bound []string) string {
	for _, d := range bound {
		if d != "" && under(path, filepath.Clean(d)) {
			return d
		}
	}
	return ""
}

// checkExec verifies exec.allow on the host before anything starts: every
// entry must be a regular file, and a pinned digest must match its content.
// Anything else refuses to start (fail closed). The check happens before
// the bind or the profile is set up; a file an attacker can rewrite in that
// window is a file they could rewrite anyway, so the pin protects against
// a package manager update, not against someone who already owns ~/.local.
func checkExec(p *policy.Policy) error {
	for _, path := range p.Exec.Allow {
		if st, err := os.Stat(path); err != nil {
			return fmt.Errorf("exec.allow: %s: %w", path, err)
		} else if !st.Mode().IsRegular() {
			return fmt.Errorf("exec.allow: %s is not a regular file", path)
		}
		want, pinned := p.Exec.SHA256[path]
		if !pinned {
			continue
		}
		got, err := fileSHA256(path)
		if err != nil {
			return fmt.Errorf("exec.sha256: %s: %w", path, err)
		}
		if got != want {
			return fmt.Errorf("exec.sha256: %s has changed (sha256 %s, pinned %s); refusing to start", path, got[:12], want[:12])
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildDarwin wraps the server in sandbox-exec with a profile generated from
// the policy. The profile is written into s.WorkDir.
func buildDarwin(p *policy.Policy, s Spec, env []string) ([]string, string, string, error) {
	sbx, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, "", "", fmt.Errorf("sandbox-exec not found; set sandbox.disabled: true")
	}
	if s.WorkDir == "" {
		return nil, "", "", fmt.Errorf("sandbox: WorkDir is required on macOS")
	}
	if p.Network.Mode == policy.NetAllowlist && s.ProxyPort == 0 {
		// Fail closed: without a proxy port the profile would have to allow
		// the whole network or none; neither is what the policy asked for.
		return nil, "", "", fmt.Errorf("network.mode=allowlist needs the filtering proxy; refusing to start without it")
	}
	var tmp string
	if p.Filesystem.Tmp {
		tmp = filepath.Join(s.WorkDir, "tmp")
		if err := os.Mkdir(tmp, 0o700); err != nil && !os.IsExist(err) {
			return nil, "", "", err
		}
		for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
			env = append(env, k+"="+tmp)
		}
	}
	home, _ := os.UserHomeDir()
	var notes []string
	toolchain, note := toolchainBind(s.Command[0], s.Protect)
	if note != "" {
		notes = append(notes, note)
	}
	cwd := cwdOr("")
	dir := "" // where the server starts: its cwd unless that is not shared
	if why := tooBroad(cwd, s.Protect); cwd != "" && why != "" && !covered(cwd, p) {
		notes = append(notes, "cwd not shared ("+why+")")
		cwd, dir = "", "/"
	}
	prof := darwinProfile(p, s, profilePaths{home: home, userTmp: os.TempDir(), privateTmp: tmp,
		toolchain: toolchain, cwd: cwd, protect: s.Protect})
	profPath := filepath.Join(s.WorkDir, "profile.sb")
	if err := os.WriteFile(profPath, []byte(prof), 0o600); err != nil {
		return nil, "", "", err
	}
	args := []string{sbx, "-f", profPath, "env", "-i"}
	args = append(args, env...)
	args = append(args, s.Command...)

	why := "sandbox-exec: home hidden, writes scoped"
	switch p.Network.Mode {
	case policy.NetNone:
		why += ", no network"
	case policy.NetAllowlist:
		why += ", net via proxy only (hard, HTTP_PROXY)"
	}
	if n := len(p.Exec.Allow); n > 0 {
		why += fmt.Sprintf(", %d exec pin(s)", n)
	}
	if len(notes) > 0 {
		why += "; " + strings.Join(notes, "; ")
	}
	return args, why, dir, nil
}

// profilePaths are the host facts the macOS profile is built from.
type profilePaths struct {
	home       string   // $HOME: hidden unless listed
	userTmp    string   // the per-user temp dir (os.TempDir): hidden
	privateTmp string   // our private tmp, or "" when filesystem.tmp is false
	toolchain  string   // toolchainPrefix of the server binary, may be ""
	cwd        string   // working directory, may be ""
	protect    []string // mcp-jail's own state: denied last, so nothing above re-allows it
}

// darwinProfile renders the sandbox-exec (SBPL) profile. Later rules win, so
// the shape is: allow everything, hide the sensitive trees, deny all writes,
// then re-allow exactly what the policy lists. Paths are resolved through
// symlinks because the sandbox matches on real paths (/tmp -> /private/tmp).
func darwinProfile(p *policy.Policy, s Spec, h profilePaths) string {
	var b strings.Builder
	b.WriteString("(version 1)\n;; generated by mcp-jail from policy " + sbQuote(p.Name) + "\n(allow default)\n")

	// Hide: the home directory, every other user's, and the per-user temp.
	hide := uniq(realPaths("/Users", h.home, h.userTmp))
	b.WriteString(";; hidden unless listed below\n(deny file* " + subpaths(hide) + ")\n")
	if h.privateTmp != "" {
		b.WriteString("(deny file* " + subpaths(realPaths("/tmp")) + ")\n")
	}
	// No writes anywhere by default.
	b.WriteString("(deny file-write*)\n(allow file-write-data (literal \"/dev/null\"))\n")

	// Re-allow what the policy and the server binary need.
	if ro := realPaths(p.Filesystem.ReadOnly...); len(ro) > 0 {
		b.WriteString(";; filesystem.read_only\n(allow file-read* " + subpaths(ro) + ")\n")
	}
	if rw := realPaths(p.Filesystem.ReadWrite...); len(rw) > 0 {
		b.WriteString(";; filesystem.read_write\n(allow file* " + subpaths(rw) + ")\n")
	}
	if h.privateTmp != "" {
		b.WriteString(";; private tmp\n(allow file* " + subpaths(realPaths(h.privateTmp)) + ")\n")
	}
	var extra []string
	if h.toolchain != "" && !covered(h.toolchain, p) {
		extra = append(extra, h.toolchain)
	}
	if h.cwd != "" && !covered(h.cwd, p) {
		extra = append(extra, h.cwd)
	}
	if ex := realPaths(extra...); len(ex) > 0 {
		b.WriteString(";; toolchain and working directory\n(allow file-read* " + subpaths(ex) + ")\n")
	}
	// Pinned executables: nothing under the hidden trees may run except the
	// directories the policy shares whole (as on Linux, where they are
	// mounted) and the listed files, which also need to be readable.
	if pins := realPaths(p.Exec.Allow...); len(pins) > 0 {
		b.WriteString(";; exec.allow: under the hidden trees only these may run\n(deny process-exec* " + subpaths(hide) + ")\n")
		if dirs := realPaths(append(append(append([]string{}, p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...), extra...)...); len(dirs) > 0 {
			b.WriteString("(allow process-exec* " + subpaths(dirs) + ")\n")
		}
		b.WriteString("(allow process-exec* " + literals(pins) + ")\n(allow file-read* " + literals(pins) + ")\n")
	}

	switch p.Network.Mode {
	case policy.NetNone:
		b.WriteString(";; network.mode none\n(deny network*)\n")
	case policy.NetAllowlist:
		b.WriteString(";; network.mode allowlist: only the filtering proxy on the host loopback\n(deny network*)\n")
		fmt.Fprintf(&b, "(allow network-outbound (remote tcp \"localhost:%d\"))\n", s.ProxyPort)
	}
	// Last, so no allow above can re-open it: mcp-jail's own state. The
	// control socket is a Unix socket, hence the network rule as well.
	if pr := realPaths(h.protect...); len(pr) > 0 {
		b.WriteString(";; mcp-jail state: policy, audit log, locks, registry, control socket\n")
		b.WriteString("(deny file* " + subpaths(pr) + ")\n(deny network* " + subpaths(pr) + ")\n")
	}
	return b.String()
}

// tooBroad reports why dir must not be shared with the jail as a
// convenience bind: it is the root, the home directory or one of its
// parents, or it holds one of the protected paths. "" means fine.
func tooBroad(dir string, protect []string) string {
	dir = filepath.Clean(dir)
	if dir == "/" || dir == "." || dir == filepath.VolumeName(dir)+string(filepath.Separator) {
		return "root"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if under(filepath.Clean(home), dir) {
			return "home"
		}
	}
	for _, p := range protect {
		if p != "" && under(filepath.Clean(p), dir) {
			return "contains mcp-jail state"
		}
	}
	return ""
}

// under reports whether path is dir itself or inside it.
func under(path, dir string) bool {
	sep := string(filepath.Separator)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, sep)+sep)
}

// toolchainBind picks the directory to expose for the server binary:
// toolchainPrefix unless that is too broad, then the binary's own
// directory, then nothing (with a note saying why).
func toolchainBind(argv0 string, protect []string) (string, string) {
	prefix := toolchainPrefix(argv0)
	if prefix == "" {
		return "", ""
	}
	why := tooBroad(prefix, protect)
	if why == "" {
		return prefix, ""
	}
	// fall back to the directory of the binary itself
	if path, err := exec.LookPath(argv0); err == nil {
		if real, err := filepath.EvalSymlinks(path); err == nil {
			path = real
		}
		if dir := filepath.Dir(path); dir != prefix && tooBroad(dir, protect) == "" {
			return dir, ""
		}
	}
	return "", "toolchain dir not shared (" + why + ")"
}

type mask struct {
	path string
	dir  bool
}

// masks lists the protected paths that exist and would be visible through
// one of the bound directories, so the Linux sandbox can cover them.
func masks(protect, bound []string) []mask {
	var out []mask
	seen := map[string]bool{}
	for _, p := range protect {
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		if seen[p] {
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		for _, b := range bound {
			if under(p, filepath.Clean(b)) {
				seen[p] = true
				out = append(out, mask{path: p, dir: st.IsDir()})
				break
			}
		}
	}
	return out
}

func subpaths(paths []string) string {
	parts := make([]string, 0, len(paths))
	for _, p := range paths {
		parts = append(parts, "(subpath "+sbQuote(p)+")")
	}
	return strings.Join(parts, " ")
}

func literals(paths []string) string {
	parts := make([]string, 0, len(paths))
	for _, p := range paths {
		parts = append(parts, "(literal "+sbQuote(p)+")")
	}
	return strings.Join(parts, " ")
}

// sbQuote renders an SBPL string literal. Control characters (a newline
// would end a comment or a rule) are replaced, never emitted.
func sbQuote(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

// realPaths resolves symlinks where possible and drops empty entries.
func realPaths(in ...string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		out = append(out, p)
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func cwdOr(def string) string {
	if d, err := os.Getwd(); err == nil {
		return d
	}
	return def
}

// toolchainPrefix resolves argv[0] through PATH and symlinks and returns the
// directory that should be visible for it to run: the parent of a ".../bin"
// directory (covers /usr/local, ~/.nvm/versions/node/vX, venvs, pyenv
// shims), otherwise the binary's own directory. Paths already under /usr,
// /bin, /sbin or /lib are covered by the base mounts and yield "".
func toolchainPrefix(argv0 string) string {
	path, err := exec.LookPath(argv0)
	if err != nil {
		return ""
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	dir := filepath.Dir(path)
	for _, base := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if strings.HasPrefix(dir+"/", base) {
			return ""
		}
	}
	if filepath.Base(dir) == "bin" {
		return filepath.Dir(dir)
	}
	return dir
}

func covered(dir string, p *policy.Policy) bool {
	for _, d := range append(append([]string{}, p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...) {
		if under(dir, d) {
			return true
		}
	}
	return false
}

// hardeningEnv is set in every jail before the policy's own variables:
// the opt-outs package managers and CLIs honour for update checks and
// telemetry, so a launcher does not phone home or fetch a newer version on
// its own. A sandbox.env entry with the same name overrides it.
var hardeningEnv = []string{"DO_NOT_TRACK=1", "NO_UPDATE_NOTIFIER=1", "npm_config_update_notifier=false"}

// passthroughEnv builds the jail's environment from sandbox.env: a bare
// NAME copies the host's value (skipped when unset), NAME=value sets it.
func passthroughEnv(keys []string) []string {
	if len(keys) == 0 {
		keys = []string{"PATH", "HOME", "LANG", "TERM"}
	}
	vals := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := vals[k]; !ok {
			order = append(order, k)
		}
		vals[k] = v
	}
	for _, kv := range hardeningEnv {
		k, v, _ := strings.Cut(kv, "=")
		set(k, v)
	}
	for _, k := range keys {
		if name, v, ok := strings.Cut(k, "="); ok {
			set(name, v)
		} else if v, ok := os.LookupEnv(k); ok {
			set(k, v)
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+vals[k])
	}
	return out
}
