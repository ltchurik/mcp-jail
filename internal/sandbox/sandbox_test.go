package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

func TestToolchainPrefix(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "node-v22", "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "node")
	writeExec(t, exe)
	link := filepath.Join(root, "node")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(root, "node-v22")) // macOS: /var -> /private/var
	if got := toolchainPrefix(link); got != want {
		t.Errorf("prefix via symlink = %q, want %q", got, want)
	}
	if got := toolchainPrefix("/usr/bin/env"); got != "" {
		t.Errorf("/usr binary should need no extra bind, got %q", got)
	}
	if got := toolchainPrefix("definitely-not-a-binary-xyz"); got != "" {
		t.Errorf("unknown binary: got %q", got)
	}
}

func TestBuildDisabled(t *testing.T) {
	p := policy.Default()
	p.Sandbox.Disabled = true
	argv, how, err := build(p, Spec{Command: []string{"srv", "--flag"}, Env: map[string]string{"HTTP_PROXY": "http://127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "env" || argv[len(argv)-2] != "srv" || argv[len(argv)-1] != "--flag" {
		t.Fatalf("argv = %v", argv)
	}
	if !contains(argv, "HTTP_PROXY=http://127.0.0.1:1") {
		t.Fatalf("extra env missing: %v", argv)
	}
	if !strings.Contains(how, "disabled") && !strings.Contains(how, "no sandbox") {
		t.Fatalf("how = %q", how)
	}
}

func TestBuildBwrapArgs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	bin := t.TempDir()
	writeExec(t, filepath.Join(bin, "bwrap"))
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("SECRET", "x")

	p := policy.Default()
	p.Network.Mode = policy.NetNone
	p.Filesystem.ReadOnly = []string{"/opt/ro"}
	p.Filesystem.ReadWrite = []string{"/opt/rw"}
	p.Sandbox.Env = []string{"PATH"}
	argv, how, err := build(p, Spec{Command: []string{"/usr/bin/true"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--unshare-net", "--unshare-pid", "--die-with-parent",
		"--ro-bind /opt/ro /opt/ro", "--bind /opt/rw /opt/rw",
		"--tmpfs /tmp", "--clearenv", "-- /usr/bin/true",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if strings.Contains(joined, "SECRET") {
		t.Errorf("env not in sandbox.env leaked: %s", joined)
	}
	if !strings.Contains(how, "no network") {
		t.Errorf("how = %q", how)
	}

	p.Network.Mode = policy.NetAll
	argv, _, _ = build(p, Spec{Command: []string{"/usr/bin/true"}})
	if contains(argv, "--unshare-net") {
		t.Error("mode all must not unshare net")
	}
}

// writeExec writes an executable fixture; tests need +x, which gosec G306 flags.
func writeExec(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestBuildHardEgress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	bin := t.TempDir()
	writeExec(t, filepath.Join(bin, "bwrap"))
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	p := policy.Default()
	p.Network.Mode = policy.NetAllowlist
	p.Network.Allow = []string{"api.github.com", "*.githubusercontent.com"}

	// Fail closed: allowlist mode without a relay must not start at all.
	if _, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}}); err == nil {
		t.Fatal("allowlist without egress relay must fail")
	}

	eg := &Egress{Dir: "/tmp/relay", Exe: "/x/mcp-jail", Allow: p.Network.Allow, UID: 1001, GID: 1002, ResolvConf: "/tmp/relay/resolv.conf"}
	argv, how, err := build(p, Spec{Command: []string{"/usr/bin/true", "-x"}, Egress: eg, Env: map[string]string{"HTTPS_PROXY": "http://127.0.0.1:3128"}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--unshare-user --uid 0 --gid 0 --cap-add CAP_NET_BIND_SERVICE --cap-add CAP_SETFCAP", "--unshare-net",
		"--ro-bind /tmp/relay/resolv.conf /etc/resolv.conf",
		"--bind /tmp/relay /run/mcp-jail", "--ro-bind /x/mcp-jail /opt/mcp-jail/mcp-jail",
		"--setenv HTTPS_PROXY http://127.0.0.1:3128",
		"-- /opt/mcp-jail/mcp-jail _egress-shim --socket /run/mcp-jail/egress.sock --allow api.github.com,*.githubusercontent.com --uid 1001 --gid 1002 -- /usr/bin/true -x",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if strings.Contains(joined, "--unshare-user-try") || strings.Contains(joined, "--ro-bind-try /etc/resolv.conf") {
		t.Errorf("hard egress must not use the soft variants: %s", joined)
	}
	if !strings.Contains(how, "egress allowlist (hard)") {
		t.Errorf("how = %q", how)
	}
	if HardEgress(p) != true {
		t.Error("HardEgress should be true on linux with sandbox enabled")
	}
	p.Sandbox.Disabled = true
	if HardEgress(p) {
		t.Error("HardEgress must be false when the sandbox is disabled")
	}
}
