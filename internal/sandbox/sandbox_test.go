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
	if got, want := toolchainPrefix(link), filepath.Join(root, "node-v22"); got != want {
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
	if !strings.Contains(how, "disabled") {
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
