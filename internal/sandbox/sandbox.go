// Package sandbox builds the command line that launches the MCP server
// inside an isolated environment.
//
// Linux: bubblewrap (bwrap) — user, mount, PID and (optionally) network
// namespaces, with only the paths from the policy visible.
// Other platforms: no isolation; mcp-jail still enforces tool policy, the
// rug-pull lock and audit logging, and prints a warning.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

// Spec is what the launcher needs beyond the policy.
type Spec struct {
	Command []string          // server command and args
	Env     map[string]string // extra env (e.g. HTTP_PROXY)
}

// Build returns an exec.Cmd for the jailed server and a description of the
// isolation that was applied (for the log line).
func Build(p *policy.Policy, s Spec) (*exec.Cmd, string, error) {
	cmd, how, err := build(p, s)
	if err != nil {
		return nil, "", err
	}
	return exec.Command(cmd[0], cmd[1:]...), how, nil
}

// build is Build without the exec.Cmd, for tests.
func build(p *policy.Policy, s Spec) ([]string, string, error) {
	if len(s.Command) == 0 {
		return nil, "", fmt.Errorf("no server command given (use: mcp-jail run --policy p.yml -- <cmd> [args])")
	}
	env := passthroughEnv(p.Sandbox.Env)
	for k, v := range s.Env {
		env = append(env, k+"="+v)
	}

	if p.Sandbox.Disabled || runtime.GOOS != "linux" {
		why := "sandbox disabled by policy"
		if runtime.GOOS != "linux" {
			why = "no sandbox on " + runtime.GOOS + " (policy/lock/audit only)"
		}
		return append([]string{"env", "-i"}, append(env, s.Command...)...), why, nil
	}

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, "", fmt.Errorf("bwrap not found; install bubblewrap or set sandbox.disabled: true")
	}

	args := []string{
		"--unshare-user-try", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--die-with-parent", "--new-session",
		"--proc", "/proc", "--dev", "/dev",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/sbin", "/sbin",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl",
		"--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
		"--ro-bind-try", "/etc/hosts", "/etc/hosts",
		"--ro-bind-try", "/etc/passwd", "/etc/passwd",
		"--ro-bind-try", "/etc/group", "/etc/group",
		"--ro-bind-try", "/etc/localtime", "/etc/localtime",
		"--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
	}
	if p.Network.Mode == policy.NetNone {
		args = append(args, "--unshare-net")
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
	if prefix := toolchainPrefix(s.Command[0]); prefix != "" && !covered(prefix, p) {
		args = append(args, "--ro-bind", prefix, prefix)
	}
	// Same for the working directory (relative script paths, package.json).
	if cwd, err := os.Getwd(); err == nil && !covered(cwd, p) {
		args = append(args, "--ro-bind", cwd, cwd, "--chdir", cwd)
	}
	args = append(args, "--clearenv")
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		args = append(args, "--setenv", k, v)
	}
	args = append(args, "--")
	args = append(args, s.Command...)

	why := "bwrap: user/pid/ipc/uts ns"
	if p.Network.Mode == policy.NetNone {
		why += ", net ns (no network)"
	}
	return append([]string{bwrap}, args...), why, nil
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
		if dir == d || strings.HasPrefix(dir, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

func passthroughEnv(keys []string) []string {
	if len(keys) == 0 {
		keys = []string{"PATH", "HOME", "LANG", "TERM"}
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}
