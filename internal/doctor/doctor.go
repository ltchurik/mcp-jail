// Package doctor checks what this host can do for mcp-jail: which sandbox
// is usable, whether the hard egress allowlist can work, whether a
// container backend is available, and where the state lives. It only
// reads and runs harmless probes; `mcp-jail doctor` prints the result.
package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Status of one check.
const (
	OK      = "ok"
	Warn    = "warn"
	Missing = "missing"
)

// Check is one line of the report.
type Check struct {
	Status string `json:"status"`
	Name   string `json:"name"`
	Detail string `json:"detail"`
	// Hint says what to do about a warn or missing; empty when ok.
	Hint string `json:"hint,omitempty"`
}

// Report is what Run returns.
type Report struct {
	Version string  `json:"version"`
	OS      string  `json:"os"`
	Arch    string  `json:"arch"`
	Checks  []Check `json:"checks"`
	// Native names the host's own sandbox when it is usable (bwrap,
	// sandbox-exec), "" otherwise. Docker is true when docker or podman
	// can run a container right now.
	Native string `json:"native"`
	Docker bool   `json:"docker"`
	// Summary is the one-line verdict; Usable is false when no sandbox at
	// all can be set up here (the exit status of the command).
	Summary string `json:"summary"`
	Usable  bool   `json:"usable"`
}

// Host is what the checks ask of the machine; tests replace it.
type Host struct {
	GOOS, GOARCH string
	Look         func(name string) (string, error)
	Run          func(name string, args ...string) (string, error) // combined output
	Read         func(path string) (string, error)
	StateDir     string // the lock directory (lock.Dir())
}

// RealHost is the machine mcp-jail runs on.
func RealHost(stateDir string) Host {
	return Host{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Look: exec.LookPath, Run: run, Read: readFile, StateDir: stateDir}
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return string(out), fmt.Errorf("timed out after 15s")
	}
	return strings.TrimSpace(string(out)), err
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}

// Run performs every check that applies to h.
func Run(h Host, version string) Report {
	r := Report{Version: version, OS: h.GOOS, Arch: h.GOARCH}
	add := func(c Check) { r.Checks = append(r.Checks, c) }
	switch h.GOOS {
	case "linux":
		r.Native = checkBwrap(h, add)
	case "darwin":
		if path, err := h.Look("sandbox-exec"); err == nil {
			add(Check{Status: OK, Name: "sandbox-exec", Detail: path})
			r.Native = "sandbox-exec"
		} else {
			add(Check{Status: Missing, Name: "sandbox-exec", Detail: "not found", Hint: "it ships with macOS; sandbox.backend: docker is the alternative"})
		}
	case "windows":
		// AppContainer is part of Windows 8 and later; icacls (System32)
		// is how the policy's directories are granted to the container.
		if path, err := h.Look("icacls"); err == nil {
			add(Check{Status: OK, Name: "appcontainer", Detail: "Windows AppContainer; grants via " + path})
			r.Native = "appcontainer"
		} else {
			add(Check{Status: Missing, Name: "appcontainer", Detail: "icacls.exe not found in PATH", Hint: "it ships in %SystemRoot%\\System32; sandbox.backend: docker is the alternative"})
		}
	default:
		add(Check{Status: Missing, Name: "native sandbox", Detail: "none on " + h.GOOS, Hint: "sandbox.backend: docker is the sandbox here (Docker Desktop or podman)"})
	}
	r.Docker = checkDocker(h, add)
	checkState(h, add)

	r.Usable = r.Native != "" || r.Docker
	switch {
	case r.Native != "" && r.Docker:
		r.Summary = "native sandbox " + r.Native + " and the docker backend are both usable"
	case r.Native != "":
		r.Summary = "native sandbox " + r.Native + " is usable; no docker or podman for sandbox.backend: docker"
	case r.Docker:
		r.Summary = "no native sandbox; use sandbox.backend: docker"
	default:
		r.Summary = "no sandbox can be set up here; mcp-jail run will refuse unless sandbox.disabled: true (policy, lock and audit only)"
	}
	return r
}

// checkBwrap reports bubblewrap, user namespaces and a probe jail; returns
// "bwrap" when a jail can be set up.
func checkBwrap(h Host, add func(Check)) string {
	path, err := h.Look("bwrap")
	if err != nil {
		add(Check{Status: Missing, Name: "bwrap", Detail: "not found", Hint: "sudo apt install bubblewrap (Debian/Ubuntu), sudo dnf install bubblewrap (Fedora); or sandbox.backend: docker"})
		return ""
	}
	ver, _ := h.Run(path, "--version") // "bubblewrap 0.9.0"
	ver = strings.TrimPrefix(ver, "bubblewrap ")
	detail := path
	if ver != "" {
		detail += " (" + ver + ")"
	}
	if major, minor, ok := semver(ver); ok && (major == 0 && minor < 5) {
		add(Check{Status: Warn, Name: "bwrap", Detail: detail, Hint: "bubblewrap 0.5 or newer is needed for the hard egress allowlist; network none and all work"})
	} else {
		add(Check{Status: OK, Name: "bwrap", Detail: detail})
	}
	usable := true
	// user namespaces: three knobs, any one of them can close the door
	if v, err := h.Read("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && v == "0" {
		add(Check{Status: Missing, Name: "user namespaces", Detail: "kernel.unprivileged_userns_clone = 0", Hint: "sudo sysctl -w kernel.unprivileged_userns_clone=1"})
		usable = false
	}
	if v, err := h.Read("/proc/sys/user/max_user_namespaces"); err == nil && v == "0" {
		add(Check{Status: Missing, Name: "user namespaces", Detail: "user.max_user_namespaces = 0", Hint: "sudo sysctl -w user.max_user_namespaces=15000"})
		usable = false
	}
	if v, err := h.Read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && v == "1" {
		add(Check{Status: Warn, Name: "user namespaces", Detail: "kernel.apparmor_restrict_unprivileged_userns = 1 (Ubuntu 24.04+)", Hint: "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0, or an AppArmor profile for bwrap"})
	}
	// the probe is what counts: a minimal jail with its own user and net namespace
	out, err := h.Run(path, "--unshare-user-try", "--unshare-net", "--ro-bind", "/usr", "/usr", "--ro-bind-try", "/bin", "/bin", "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--", "/usr/bin/true")
	if err != nil {
		add(Check{Status: Missing, Name: "bwrap probe", Detail: oneLine(out, err), Hint: "a jail cannot be set up: see the user namespace lines above, or use sandbox.backend: docker"})
		return ""
	}
	add(Check{Status: OK, Name: "bwrap probe", Detail: "user + net namespace jail starts"})
	if !usable {
		return ""
	}
	return "bwrap"
}

// checkDocker reports docker, then podman; true when a daemon answers.
func checkDocker(h Host, add func(Check)) bool {
	for _, name := range []string{"docker", "podman"} {
		path, err := h.Look(name)
		if err != nil {
			continue
		}
		out, err := h.Run(path, "info", "--format", "{{.ServerVersion}}")
		if err != nil || out == "" {
			hint := "start it: open -a Docker (Docker Desktop), sudo systemctl start docker, or podman machine start"
			add(Check{Status: Warn, Name: name, Detail: path + ": installed, no daemon (" + oneLine(out, err) + ")", Hint: hint})
			continue
		}
		detail := path + " (daemon " + out + ")"
		if h.GOOS != "linux" {
			detail += "; network.mode allowlist with the docker backend needs a Linux host, none and all work"
		}
		add(Check{Status: OK, Name: name, Detail: detail})
		return true
	}
	if _, err := h.Look("docker"); err != nil {
		if _, err := h.Look("podman"); err != nil {
			add(Check{Status: Missing, Name: "docker", Detail: "neither docker nor podman found", Hint: "optional: Docker Desktop or podman enable sandbox.backend: docker"})
		}
	}
	return false
}

// checkState reports where locks, policies and the registry live.
func checkState(h Host, add func(Check)) {
	dir := h.StateDir
	if dir == "" {
		add(Check{Status: Warn, Name: "state", Detail: "no state directory"})
		return
	}
	base := filepath.Dir(dir)
	st, err := os.Stat(dir)
	switch {
	case err == nil && st.IsDir():
		n := 0
		if ents, err := os.ReadDir(dir); err == nil {
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), ".lock.json") {
					n++
				}
			}
		}
		add(Check{Status: OK, Name: "state", Detail: fmt.Sprintf("%s (%d lock(s); policies and run/ next to it)", base, n)})
	case err == nil:
		add(Check{Status: Missing, Name: "state", Detail: dir + " is not a directory", Hint: "move it away; mcp-jail creates the directory itself"})
	default:
		add(Check{Status: OK, Name: "state", Detail: base + " (not created yet; the first run does)"})
	}
}

func semver(v string) (major, minor int, ok bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	return major, minor, err1 == nil && err2 == nil
}

func oneLine(out string, err error) string {
	s := strings.TrimSpace(out)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if s == "" && err != nil {
		s = err.Error()
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
