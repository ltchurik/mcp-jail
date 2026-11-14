package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

// The AppContainer backend is the native sandbox on Windows. Go's os/exec
// cannot attach the security capabilities a lowbox process is created with,
// so the server is started by mcp-jail itself, re-executed as a hidden
// subcommand the way the egress shim is: the jail runs
// `mcp-jail _appcontainer <options> -- <cmd>`, and that process creates the
// AppContainer profile, grants its SID access to the policy's directories,
// starts the server inside the container and waits for it (see
// appcontainer_windows.go). With --plain the same subcommand only scrubs the
// environment and ties the server's lifetime to its own: that is
// sandbox.disabled on Windows, which has no `env -i`.

// AppContainerCommand is the hidden subcommand the Windows launcher runs.
const AppContainerCommand = "_appcontainer"

// AppContainerOptions is what the launcher receives on its command line.
type AppContainerOptions struct {
	Profile   string   // AppContainer profile name
	Plain     bool     // no container: environment and lifetime only (sandbox disabled)
	Network   string   // none | all
	ReadOnly  []string // directories the container SID may read and execute
	ReadWrite []string // directories it may modify
	Deny      []string // paths inside granted directories it must not see (mcp-jail's own state)
	Env       []string // sandbox.env entries (NAME or NAME=value)
	Set       []string // NAME=value extras from the jail (proxy settings)
	Cwd       string   // working directory; "" is the container's private home
	Command   []string
}

// buildWindows returns the launcher argv for the AppContainer backend.
func buildWindows(p *policy.Policy, s Spec) ([]string, string, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, "", "", fmt.Errorf("appcontainer: locate mcp-jail binary: %w", err)
	}
	if p.Network.Mode == policy.NetAllowlist {
		return nil, "", "", fmt.Errorf("network.mode allowlist cannot be enforced under AppContainer: Windows blocks an AppContainer's loopback connections, so the filtering proxy is out of reach; use none or all (or sandbox.backend: none for the cooperative proxy)")
	}
	if len(p.Exec.Allow) > 0 {
		return nil, "", "", fmt.Errorf("exec.allow cannot be enforced with sandbox.backend appcontainer: list the toolchain directory in filesystem.read_only instead")
	}
	o := AppContainerOptions{Profile: profileName(p.Name), Network: string(p.Network.Mode),
		ReadOnly: append([]string{}, p.Filesystem.ReadOnly...), ReadWrite: append([]string{}, p.Filesystem.ReadWrite...),
		Env: p.Sandbox.Env, Command: s.Command}
	var notes []string
	bound := append(append([]string{}, p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...)
	if prefix, note := toolchainBind(s.Command[0], s.Protect); prefix != "" && !covered(prefix, p) {
		o.ReadOnly = append(o.ReadOnly, prefix)
		bound = append(bound, prefix)
	} else if note != "" {
		notes = append(notes, note)
	}
	if cwd, err := os.Getwd(); err == nil {
		switch {
		case covered(cwd, p):
			o.Cwd = cwd
		case tooBroad(cwd, s.Protect) == "":
			o.ReadOnly = append(o.ReadOnly, cwd)
			bound = append(bound, cwd)
			o.Cwd = cwd
		default:
			notes = append(notes, "cwd not shared ("+tooBroad(cwd, s.Protect)+")")
		}
	}
	for _, m := range masks(s.Protect, bound) {
		o.Deny = append(o.Deny, m.path)
	}
	for _, k := range sortedKeys(s.Env) {
		o.Set = append(o.Set, k+"="+s.Env[k])
	}
	how := fmt.Sprintf("appcontainer: %s, %d dir(s) granted (%d read-only)", o.Profile, len(o.ReadOnly)+len(o.ReadWrite), len(o.ReadOnly))
	if p.Network.Mode == policy.NetNone {
		how += ", no network"
	} else {
		how += ", network all"
	}
	if len(notes) > 0 {
		how += "; " + strings.Join(notes, "; ")
	}
	return appContainerArgv(exe, o), how, "", nil
}

// buildWindowsPlain starts the server without a container (sandbox
// disabled): the launcher scrubs the environment the way `env -i` does on
// Unix and ends the server when it ends itself.
func buildWindowsPlain(p *policy.Policy, s Spec, how string) ([]string, string, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, "", "", fmt.Errorf("locate mcp-jail binary: %w", err)
	}
	o := AppContainerOptions{Plain: true, Env: p.Sandbox.Env, Command: s.Command}
	for _, k := range sortedKeys(s.Env) {
		o.Set = append(o.Set, k+"="+s.Env[k])
	}
	return appContainerArgv(exe, o), how, "", nil
}

// appContainerArgv is the inverse of the flag parsing in cmd/mcp-jail.
func appContainerArgv(exe string, o AppContainerOptions) []string {
	argv := []string{exe, AppContainerCommand}
	if o.Plain {
		argv = append(argv, "--plain")
	} else {
		argv = append(argv, "--profile", o.Profile, "--net", o.Network)
	}
	for _, d := range o.ReadOnly {
		argv = append(argv, "--ro", d)
	}
	for _, d := range o.ReadWrite {
		argv = append(argv, "--rw", d)
	}
	for _, d := range o.Deny {
		argv = append(argv, "--deny", d)
	}
	for _, e := range o.Env {
		argv = append(argv, "--env", e)
	}
	for _, e := range o.Set {
		argv = append(argv, "--set", e)
	}
	if o.Cwd != "" {
		argv = append(argv, "--cwd", o.Cwd)
	}
	return append(append(argv, "--"), o.Command...)
}

// profileName is the AppContainer profile for a policy: deterministic, so a
// run after a crash finds the grants its predecessor left and the profile's
// folder (npm and uv caches) is reused; at most 64 characters, from the
// set Windows accepts.
func profileName(policyName string) string {
	var b strings.Builder
	for _, r := range policyName {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := b.String()
	if len(name) > 40 {
		name = name[:40]
	}
	sum := sha256.Sum256([]byte(policyName))
	return "mcp-jail-" + name + "-" + hex.EncodeToString(sum[:4])
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// appContainerNotes are what show reports for the AppContainer backend.
func appContainerNotes(p *policy.Policy) []string {
	var notes []string
	if p.Network.Mode == policy.NetAllowlist {
		notes = append(notes, "allowlist cannot be enforced under AppContainer (loopback to the proxy is blocked): the jail will refuse to start; use none or all")
	}
	if len(p.Exec.Allow) > 0 {
		notes = append(notes, "exec.allow cannot be enforced with sandbox.backend appcontainer: the jail will refuse to start")
	}
	if runtime.GOOS != "windows" {
		notes = append(notes, "sandbox.backend appcontainer needs Windows (this is "+runtime.GOOS+"): the jail will refuse to start")
	}
	return notes
}
