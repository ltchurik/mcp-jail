package sandbox

import (
	"os"
	"runtime"
	"strings"

	"github.com/ltchurik/mcp-jail/internal/launcher"
	"github.com/ltchurik/mcp-jail/internal/policy"
)

// Plan describes the jail Build would set up for a policy on this host,
// computed without starting anything: what `mcp-jail show` prints. It is
// derived with the same helpers Build uses (toolchain prefix, working
// directory, masks), so it names the mounts a server really gets.
type Plan struct {
	// Kind is bwrap, sandbox-exec, appcontainer, docker, none (a platform
	// without a sandbox), disabled (sandbox.disabled) or remote (server.url).
	Kind string `json:"kind"`
	// Image is the container image of the docker backend; "" otherwise.
	Image string `json:"image,omitempty"`
	// Base lists host paths every Linux jail sees read-only.
	Base      []string `json:"base,omitempty"`
	ReadOnly  []string `json:"read_only"`
	ReadWrite []string `json:"read_write"`
	Tmp       bool     `json:"tmp"`
	// Toolchain is the prefix bound read-only so the server binary can start.
	Toolchain string `json:"toolchain,omitempty"`
	// Cwd is the working directory when it is shared read-only.
	Cwd string `json:"cwd,omitempty"`
	// Masked are mcp-jail's own files hidden inside otherwise visible dirs.
	Masked []string `json:"masked,omitempty"`
	// Hidden are the trees a macOS profile denies unless listed.
	Hidden  []string `json:"hidden,omitempty"`
	Network string   `json:"network"`
	Allow   []string `json:"allow,omitempty"`
	// Hard reports whether the network mode is enforced by the OS rather
	// than by a cooperative HTTP_PROXY.
	Hard bool `json:"hard"`
	// Env lists the variable names set in the jail: the policy's
	// sandbox.env plus the update-check and telemetry opt-outs every jail
	// gets (DO_NOT_TRACK, NO_UPDATE_NOTIFIER, npm_config_update_notifier).
	Env []string `json:"env"`
	// Exec lists the pinned executables (exec.allow) and their state on
	// this host right now.
	Exec  []ExecPin `json:"exec,omitempty"`
	Notes []string  `json:"notes,omitempty"`
}

// ExecPin is one exec.allow entry as found on the host.
type ExecPin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"` // the pinned digest, if any
	// Status is ok, not pinned (allowed, no digest), missing, not a regular
	// file, or sha256 mismatch.
	Status string `json:"status"`
}

// execPins reports the state of every exec.allow entry without refusing.
func execPins(p *policy.Policy) []ExecPin {
	var out []ExecPin
	for _, path := range p.Exec.Allow {
		pin := ExecPin{Path: path, SHA256: p.Exec.SHA256[path]}
		st, err := os.Stat(path)
		switch {
		case err != nil:
			pin.Status = "missing"
		case !st.Mode().IsRegular():
			pin.Status = "not a regular file"
		case pin.SHA256 == "":
			pin.Status = "not pinned"
		default:
			got, err := fileSHA256(path)
			switch {
			case err != nil:
				pin.Status = "unreadable"
			case got != pin.SHA256:
				pin.Status = "sha256 mismatch"
			default:
				pin.Status = "ok"
			}
		}
		out = append(out, pin)
	}
	return out
}

// linuxBase are the read-only binds every bwrap jail starts with.
var linuxBase = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ssl", "/etc/ca-certificates",
	"/etc/hosts", "/etc/passwd", "/etc/group", "/etc/localtime", "/etc/nsswitch.conf", "/etc/resolv.conf"}

// Explain computes the Plan for p and s on this host.
func Explain(p *policy.Policy, s Spec) Plan {
	plan := Plan{ReadOnly: append([]string{}, p.Filesystem.ReadOnly...), ReadWrite: append([]string{}, p.Filesystem.ReadWrite...),
		Tmp: p.Filesystem.Tmp, Network: string(p.Network.Mode), Allow: p.Network.Allow}
	if p.Network.Mode != policy.NetAllowlist {
		plan.Allow = nil
	}
	for _, kv := range passthroughEnv(p.Sandbox.Env) {
		k, _, _ := strings.Cut(kv, "=")
		plan.Env = append(plan.Env, k)
	}
	// what the command line resolves at start applies whatever the sandbox
	plan.Notes = append(plan.Notes, launcher.Check(s.Command)...)
	switch {
	case p.Remote():
		plan.Kind = "remote"
		plan.ReadOnly, plan.ReadWrite, plan.Tmp, plan.Env = nil, nil, false, nil
		plan.Notes = append(plan.Notes, "no server process: sandbox, filesystem and network sections do not apply")
		return plan
	case p.Sandbox.Disabled:
		plan.Kind = "disabled"
		plan.Notes = append(plan.Notes, "sandbox.disabled: policy, lock and audit only; the server sees the whole machine")
		return plan
	case p.Sandbox.Backend == policy.BackendDocker:
		return explainDocker(p, s, plan)
	case p.Sandbox.Backend == policy.BackendAppContainer && runtime.GOOS != "windows":
		plan.Kind = "appcontainer"
		plan.Notes = append(plan.Notes, appContainerNotes(p)...)
		return plan
	case runtime.GOOS == "windows":
		plan.Kind = "appcontainer"
		plan.Hard = p.Network.Mode != policy.NetAllowlist // allowlist is refused: nothing is enforced
		plan.Notes = append(plan.Notes, appContainerNotes(p)...)
	case runtime.GOOS == "linux":
		plan.Kind = "bwrap"
		plan.Base = linuxBase
		plan.Hard = true
	case runtime.GOOS == "darwin":
		plan.Kind = "sandbox-exec"
		home, _ := os.UserHomeDir()
		plan.Hidden = uniq(realPaths("/Users", home, os.TempDir()))
		plan.Hard = true
		if p.Network.Mode == policy.NetAllowlist {
			plan.Notes = append(plan.Notes, "allowlist: HTTP(S) through the filtering proxy only; a server that ignores HTTP_PROXY has no network")
		}
	default:
		plan.Kind = "none"
		plan.Notes = append(plan.Notes, "no sandbox on "+runtime.GOOS+": policy, lock and audit only")
		return plan
	}
	plan.Notes = append(plan.Notes, p.MountWarnings()...)
	bound := append(append([]string{}, p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...)
	if len(s.Command) > 0 {
		if prefix, note := toolchainBind(s.Command[0], s.Protect); prefix != "" && !covered(prefix, p) {
			plan.Toolchain = prefix
			bound = append(bound, prefix)
		} else if note != "" {
			plan.Notes = append(plan.Notes, note)
		}
	}
	if cwd, err := os.Getwd(); err == nil && !covered(cwd, p) {
		if why := tooBroad(cwd, s.Protect); why == "" {
			plan.Cwd = cwd
			bound = append(bound, cwd)
		} else {
			plan.Notes = append(plan.Notes, "cwd not shared ("+why+")")
		}
	}
	for _, m := range masks(s.Protect, bound) {
		plan.Masked = append(plan.Masked, m.path)
	}
	plan.Exec = execPins(p)
	for _, pin := range plan.Exec {
		if dir := coveredBy(pin.Path, bound); dir != "" {
			plan.Notes = append(plan.Notes, "exec.allow "+pin.Path+" is inside "+dir+", which is shared whole: its siblings are executable too")
		}
	}
	return plan
}
