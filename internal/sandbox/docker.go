package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

// The docker backend runs the server in a container: the image is the
// toolchain, the policy's paths are bind-mounted at their host paths (so tool
// arguments keep working), everything else of the host is absent. It is the
// only sandbox on Windows and a way to run a server whose toolchain is not
// installed on the host. The container is started with every capability
// dropped, no-new-privileges, a read-only root, a private /tmp and, unless
// sandbox.env says otherwise, HOME=/tmp.
//
// network.mode allowlist is hard on a Linux host: the container has no
// network and the egress relay's socket directory is mounted into it, with
// the mcp-jail binary as the shim (as under bwrap). Docker Desktop cannot
// pass a Unix socket into its VM, so on other hosts the allowlist is refused
// rather than downgraded to a cooperative proxy.

// defaultImages maps a launcher to the image used when sandbox.image is
// empty. Floating tags: the note printed on start says to pin one.
var defaultImages = map[string]string{
	"node": "node:22-slim", "npx": "node:22-slim", "npm": "node:22-slim",
	"bun": "oven/bun:1-slim", "bunx": "oven/bun:1-slim",
	"uv": "ghcr.io/astral-sh/uv:python3.12-bookworm-slim", "uvx": "ghcr.io/astral-sh/uv:python3.12-bookworm-slim",
	"python": "python:3.12-slim", "python3": "python:3.12-slim",
}

// dockerImage returns the image for p and the launcher of s, and a note
// when it was derived rather than configured.
func dockerImage(p *policy.Policy, s Spec) (image, note string, err error) {
	if p.Sandbox.Image != "" {
		return p.Sandbox.Image, "", nil
	}
	launcher := ""
	if len(s.Command) > 0 {
		launcher = filepath.Base(s.Command[0])
	}
	img, ok := defaultImages[launcher]
	if !ok {
		return "", "", fmt.Errorf("sandbox.backend docker: set sandbox.image (no default image for %q)", launcher)
	}
	return img, "image " + img + " derived from " + launcher + "; pin one with sandbox.image (ideally with @sha256:…)", nil
}

// dockerCLI finds docker, then podman.
func dockerCLI() (string, error) {
	for _, name := range []string{"docker", "podman"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("sandbox.backend docker: neither docker nor podman found in PATH")
}

func buildDocker(p *policy.Policy, s Spec, env []string) ([]string, string, string, error) {
	cli, err := dockerCLI()
	if err != nil {
		return nil, "", "", err
	}
	if len(p.Exec.Allow) > 0 {
		return nil, "", "", fmt.Errorf("exec.allow cannot be enforced with sandbox.backend docker: the image is the pin")
	}
	image, imgNote, err := dockerImage(p, s)
	if err != nil {
		return nil, "", "", err
	}
	hard := p.Network.Mode == policy.NetAllowlist
	if hard && s.Egress == nil {
		// Fail closed: no cooperative proxy through a container boundary.
		if runtime.GOOS != "linux" {
			return nil, "", "", fmt.Errorf("network.mode=allowlist with sandbox.backend docker needs a Linux host (Docker Desktop cannot pass the relay socket into its VM); use network.mode none or all, or the native sandbox")
		}
		return nil, "", "", fmt.Errorf("network.mode=allowlist needs the egress relay; refusing to start without it")
	}
	args := []string{"run", "--rm", "-i", "--init",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--read-only", "--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())}
	if p.Filesystem.Tmp {
		// exec: npx and uvx run what they download from their cache under HOME
		args = append(args, "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=1g")
	} else {
		args = append(args, "-v", "/tmp:/tmp")
	}
	bind := func(host, guest string, ro bool) error {
		if strings.ContainsAny(host, ":,") || strings.ContainsAny(guest, ":,") {
			return fmt.Errorf("sandbox.backend docker: cannot mount %q (':' or ',' in the path)", host)
		}
		spec := host + ":" + guest
		if ro {
			spec += ":ro"
		}
		args = append(args, "-v", spec)
		return nil
	}
	var notes []string
	if imgNote != "" {
		notes = append(notes, imgNote)
	}
	if n := commandNote(s); n != "" {
		notes = append(notes, n)
	}
	switch {
	case hard:
		args = append(args, "--network", "none", "--sysctl", "net.ipv4.ip_unprivileged_port_start=0")
		for _, m := range []struct {
			host, guest string
			ro          bool
		}{{s.Egress.ResolvConf, "/etc/resolv.conf", true}, {s.Egress.Dir, jailRunDir, false}, {s.Egress.Exe, jailExe, true}} {
			if err := bind(m.host, m.guest, m.ro); err != nil {
				return nil, "", "", err
			}
		}
	case p.Network.Mode == policy.NetNone:
		args = append(args, "--network", "none")
	}
	bound := append(append([]string{}, p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...)
	for _, d := range p.Filesystem.ReadOnly {
		if err := bind(d, d, true); err != nil {
			return nil, "", "", err
		}
	}
	for _, d := range p.Filesystem.ReadWrite {
		if err := bind(d, d, false); err != nil {
			return nil, "", "", err
		}
	}
	// The working directory as under bwrap: shared read-only unless that
	// would expose the home directory or our own state.
	workdir := "/"
	if cwd, err := os.Getwd(); err == nil && !covered(cwd, p) {
		if why := tooBroad(cwd, s.Protect); why == "" {
			if err := bind(cwd, cwd, true); err != nil {
				return nil, "", "", err
			}
			bound = append(bound, cwd)
			workdir = cwd
		} else {
			notes = append(notes, "cwd not shared ("+why+")")
		}
	} else if err == nil {
		workdir = cwd
	}
	args = append(args, "-w", workdir)
	for _, m := range masks(s.Protect, bound) {
		if m.dir {
			args = append(args, "--tmpfs", m.path)
		} else if err := bind("/dev/null", m.path, true); err != nil {
			return nil, "", "", err
		}
	}
	// The host's home does not exist in the container, so a passed-through
	// HOME would point npx and uvx at an unwritable path: HOME is /tmp
	// unless sandbox.env sets one explicitly (HOME=/path).
	explicitHome := false
	for _, e := range p.Sandbox.Env {
		if strings.HasPrefix(e, "HOME=") {
			explicitHome = true
		}
	}
	kept := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") && !explicitHome {
			continue
		}
		kept = append(kept, kv)
	}
	if !explicitHome {
		kept = append(kept, "HOME=/tmp")
	}
	for _, kv := range kept {
		args = append(args, "-e", kv)
	}
	args = append(args, image)
	if hard {
		args = append(args, jailExe, ShimCommand, "--plain",
			"--socket", jailRunDir+"/egress.sock",
			"--allow", strings.Join(s.Egress.Allow, ","), "--")
	}
	args = append(args, s.Command...)

	why := filepath.Base(cli) + ": " + image + ", caps dropped, read-only root"
	switch {
	case hard:
		why += ", no network + egress allowlist (hard)"
	case p.Network.Mode == policy.NetNone:
		why += ", no network"
	}
	if len(notes) > 0 {
		why += "; " + strings.Join(notes, "; ")
	}
	return append([]string{cli}, args...), why, "", nil
}

// commandNote warns when the server command is a host path: it is resolved
// inside the image, where a host's interpreter path usually does not exist.
func commandNote(s Spec) string {
	if len(s.Command) > 0 && filepath.IsAbs(s.Command[0]) {
		return "command " + s.Command[0] + " is resolved inside the image; use a bare name (" + filepath.Base(s.Command[0]) + ") unless the image has that path"
	}
	return ""
}

// Prepare does what must happen before Build's command can start: for the
// docker backend, the image has to be present, or `docker run` would pull
// it with a progress bar on stderr while the client waits for the
// handshake. A missing image is pulled quietly here, with one log line;
// a pull that fails refuses the start. Other backends have nothing to do.
func Prepare(p *policy.Policy, s Spec, logf func(string, ...any)) error {
	if p.Sandbox.Backend != policy.BackendDocker || p.Sandbox.Disabled {
		return nil
	}
	cli, err := dockerCLI()
	if err != nil {
		return err
	}
	image, _, err := dockerImage(p, s)
	if err != nil {
		return err
	}
	if out, err := exec.Command(cli, "image", "inspect", "--format", "{{.Id}}", image).Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return nil
	}
	if logf != nil {
		logf("docker: pulling %s (not present locally)", image)
	}
	out, err := exec.Command(cli, "pull", "--quiet", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sandbox.backend docker: pull %s: %s", image, oneLine(string(out), err))
	}
	return nil
}

func oneLine(s string, err error) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if s == "" && err != nil {
		s = err.Error()
	}
	return s
}

// explainDocker fills the Plan for the docker backend.
func explainDocker(p *policy.Policy, s Spec, plan Plan) Plan {
	plan.Kind = "docker"
	image, note, err := dockerImage(p, s)
	switch {
	case err != nil:
		plan.Notes = append(plan.Notes, err.Error())
	case note != "":
		plan.Image = image
		plan.Notes = append(plan.Notes, note)
	default:
		plan.Image = image
	}
	if _, err := dockerCLI(); err != nil {
		plan.Notes = append(plan.Notes, err.Error())
	}
	if n := commandNote(s); n != "" {
		plan.Notes = append(plan.Notes, n)
	}
	plan.Notes = append(plan.Notes, p.ImageWarnings()...)
	plan.Hard = true
	if p.Network.Mode == policy.NetAllowlist && runtime.GOOS != "linux" {
		plan.Hard = false
		plan.Notes = append(plan.Notes, "allowlist needs a Linux host with the docker backend: the jail will refuse to start here")
	}
	if len(p.Exec.Allow) > 0 {
		plan.Notes = append(plan.Notes, "exec.allow cannot be enforced with sandbox.backend docker: the jail will refuse to start")
	}
	plan.Notes = append(plan.Notes, p.MountWarnings()...)
	if !slices.Contains(plan.Env, "HOME") {
		plan.Env = append(plan.Env, "HOME")
	}
	bound := append(append([]string{}, p.Filesystem.ReadOnly...), p.Filesystem.ReadWrite...)
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
	return plan
}
