package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

// fakeDocker puts an executable named docker first in PATH.
func fakeDocker(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	writeExec(t, filepath.Join(bin, "docker"))
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
}

func dockerPolicy() *policy.Policy {
	p := policy.Default()
	p.Sandbox.Backend = policy.BackendDocker
	p.Sandbox.Image = "python:3.12-slim"
	p.Network.Mode = policy.NetNone
	return p
}

func TestBuildDockerArgs(t *testing.T) {
	fakeDocker(t)
	p := dockerPolicy()
	p.Filesystem.ReadOnly = []string{"/opt/ro"}
	p.Filesystem.ReadWrite = []string{"/opt/rw"}
	p.Sandbox.Env = []string{"LANG=C"}
	argv, how, _, err := build(p, Spec{Command: []string{"python3", "srv.py"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"docker run --rm -i --init --cap-drop ALL --security-opt no-new-privileges --read-only --user ",
		"--tmpfs /tmp:rw,exec,nosuid,nodev,size=1g", "--network none",
		"-v /opt/ro:/opt/ro:ro", "-v /opt/rw:/opt/rw", "-e LANG=C", "-e HOME=/tmp", "-e DO_NOT_TRACK=1",
		" python:3.12-slim python3 srv.py",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if !strings.HasSuffix(joined, "python:3.12-slim python3 srv.py") {
		t.Errorf("image must come right before the command: %s", joined)
	}
	if !strings.Contains(how, "docker: python:3.12-slim") || !strings.Contains(how, "no network") {
		t.Errorf("how = %q", how)
	}
}

func TestBuildDockerDerivesTheImage(t *testing.T) {
	fakeDocker(t)
	p := dockerPolicy()
	p.Sandbox.Image = ""
	argv, how, _, err := build(p, Spec{Command: []string{"npx", "-y", "srv@1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "node:22-slim") || !strings.Contains(how, "derived from npx") {
		t.Fatalf("argv %v how %q", argv, how)
	}
	if _, _, _, err := build(p, Spec{Command: []string{"./srv"}}); err == nil || !strings.Contains(err.Error(), "sandbox.image") {
		t.Fatalf("unknown launcher must need an image: %v", err)
	}
}

func TestBuildDockerHome(t *testing.T) {
	fakeDocker(t)
	t.Setenv("HOME", "/Users/someone")
	p := dockerPolicy()
	p.Sandbox.Env = []string{"HOME", "PATH"} // a passed-through HOME is replaced
	argv, _, _, err := build(p, Spec{Command: []string{"srv"}})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "HOME=/tmp") || contains(argv, "HOME=/Users/someone") {
		t.Fatalf("passed-through HOME must become /tmp: %v", argv)
	}
	p.Sandbox.Env = []string{"HOME=/work"} // an explicit one is kept
	argv, _, _, err = build(p, Spec{Command: []string{"srv"}})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "HOME=/work") || contains(argv, "HOME=/tmp") {
		t.Fatalf("explicit HOME must be kept: %v", argv)
	}
}

func TestBuildDockerRefusals(t *testing.T) {
	fakeDocker(t)
	p := dockerPolicy()
	p.Exec.Allow = []string{"/usr/local/bin/srv"}
	if _, _, _, err := build(p, Spec{Command: []string{"srv"}}); err == nil || !strings.Contains(err.Error(), "exec.allow") {
		t.Fatalf("exec.allow: %v", err)
	}
	p = dockerPolicy()
	p.Network.Mode = policy.NetAllowlist
	p.Network.Allow = []string{"api.example.com"}
	_, _, _, err := build(p, Spec{Command: []string{"srv"}, ProxyPort: 1234})
	switch {
	case err == nil:
		t.Fatal("allowlist without the relay must be refused")
	case runtime.GOOS == "linux" && !strings.Contains(err.Error(), "egress relay"):
		t.Fatalf("linux: %v", err)
	case runtime.GOOS != "linux" && !strings.Contains(err.Error(), "Linux host"):
		t.Fatalf("%s: %v", runtime.GOOS, err)
	}
	p.Filesystem.ReadOnly = []string{"/opt/a:b"}
	p.Network.Mode = policy.NetNone
	if _, _, _, err := build(p, Spec{Command: []string{"srv"}}); err == nil || !strings.Contains(err.Error(), "cannot mount") {
		t.Fatalf("colon in a path: %v", err)
	}
}

func TestBuildDockerNoCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, _, _, err := build(dockerPolicy(), Spec{Command: []string{"srv"}}); err == nil || !strings.Contains(err.Error(), "neither docker nor podman") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildDockerHardEgress(t *testing.T) {
	fakeDocker(t)
	p := dockerPolicy()
	p.Network.Mode = policy.NetAllowlist
	p.Network.Allow = []string{"api.example.com", "127.0.0.1"}
	eg := &Egress{Dir: "/tmp/relay", Exe: "/usr/local/bin/mcp-jail", Allow: p.Network.Allow, UID: 1000, GID: 1000, ResolvConf: "/tmp/relay/resolv.conf"}
	argv, how, _, err := build(p, Spec{Command: []string{"srv"}, Egress: eg, Env: map[string]string{"HTTP_PROXY": "http://127.0.0.1:3128"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--network none", "--sysctl net.ipv4.ip_unprivileged_port_start=0",
		"-v /tmp/relay/resolv.conf:/etc/resolv.conf:ro", "-v /tmp/relay:/run/mcp-jail", "-v /usr/local/bin/mcp-jail:/opt/mcp-jail/mcp-jail:ro",
		"-e HTTP_PROXY=http://127.0.0.1:3128",
		"python:3.12-slim /opt/mcp-jail/mcp-jail _egress-shim --plain --socket /run/mcp-jail/egress.sock --allow api.example.com,127.0.0.1 -- srv",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if !strings.Contains(how, "egress allowlist (hard)") {
		t.Errorf("how = %q", how)
	}
}

func TestExplainDocker(t *testing.T) {
	fakeDocker(t)
	p := dockerPolicy()
	p.Sandbox.Image = ""
	plan := Explain(p, Spec{Command: []string{"uvx", "srv"}})
	if plan.Kind != "docker" || plan.Image != "ghcr.io/astral-sh/uv:python3.12-bookworm-slim" || !plan.Hard {
		t.Fatalf("plan: %+v", plan)
	}
	if !contains(plan.Env, "HOME") || !contains(plan.Env, "DO_NOT_TRACK") {
		t.Fatalf("env: %v", plan.Env)
	}
	if !strings.Contains(strings.Join(plan.Notes, "\n"), "derived from uvx") {
		t.Fatalf("notes: %v", plan.Notes)
	}
	p.Network.Mode = policy.NetAllowlist
	p.Network.Allow = []string{"api.example.com"}
	plan = Explain(p, Spec{Command: []string{"uvx", "srv"}})
	if (runtime.GOOS == "linux") != plan.Hard {
		t.Fatalf("allowlist hard=%v on %s: %v", plan.Hard, runtime.GOOS, plan.Notes)
	}
}
