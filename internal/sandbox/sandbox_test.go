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

func TestDarwinProfile(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	mk := func(rel string) string {
		d := filepath.Join(root, rel)
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		return d
	}
	home := mk("home")
	ro := mk("home/projects")
	rw := mk("home/projects/scratch")
	userTmp := mk("vartmp")
	priv := mk("work/tmp")
	tool := mk("home/.nvm/node-v22")
	// a symlink to the rw dir: the profile must contain the real path
	link := filepath.Join(root, "rw-link")
	if err := os.Symlink(rw, link); err != nil {
		t.Fatal(err)
	}

	p := policy.Default()
	p.Name = "fs \"quoted\""
	p.Network.Mode = policy.NetAllowlist
	p.Filesystem.ReadOnly = []string{ro}
	p.Filesystem.ReadWrite = []string{link}
	prof := darwinProfile(p, Spec{ProxyPort: 4567}, profilePaths{home: home, userTmp: userTmp, privateTmp: priv, toolchain: tool, cwd: ro})

	for _, want := range []string{
		"(version 1)", "(allow default)",
		`(deny file* (subpath "/Users") (subpath "` + home + `") (subpath "` + userTmp + `"))`,
		`(deny file* ` + subpaths(realPaths("/tmp")) + `)`, // /private/tmp on macOS, /tmp elsewhere
		"(deny file-write*)", `(allow file-write-data (literal "/dev/null"))`,
		`(allow file-read* (subpath "` + ro + `"))`,
		`(allow file* (subpath "` + rw + `"))`, // symlink resolved
		`(allow file* (subpath "` + priv + `"))`,
		`(allow file-read* (subpath "` + tool + `"))`,
		"(deny network*)", `(allow network-outbound (remote tcp "localhost:4567"))`,
		`policy "fs \"quoted\""`,
	} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q:\n%s", want, prof)
		}
	}
	if strings.Contains(prof, link) {
		t.Errorf("symlink must be resolved: %s", prof)
	}
	// cwd is inside read_only: no separate rule for it
	if strings.Count(prof, `(subpath "`+ro+`")`) != 1 {
		t.Errorf("cwd covered by read_only should not be listed twice:\n%s", prof)
	}
	// Re-allows must come after the denies: later rules win in SBPL.
	if strings.Index(prof, "(deny file-write*)") > strings.Index(prof, `(allow file* (subpath "`+rw+`"))`) {
		t.Error("write re-allow must follow the global write deny")
	}

	p.Network.Mode = policy.NetNone
	p.Filesystem.Tmp = false
	prof = darwinProfile(p, Spec{}, profilePaths{home: home, userTmp: userTmp})
	if !strings.Contains(prof, "(deny network*)") || strings.Contains(prof, "network-outbound") {
		t.Errorf("mode none: %s", prof)
	}
	if strings.Contains(prof, `(deny file* `+subpaths(realPaths("/tmp"))+`)`) {
		t.Errorf("tmp:false must not hide the shared /tmp: %s", prof)
	}
	p.Network.Mode = policy.NetAll
	prof = darwinProfile(p, Spec{}, profilePaths{home: home})
	if strings.Contains(prof, "network") {
		t.Errorf("mode all must not mention the network: %s", prof)
	}
}

func TestBuildDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	p := policy.Default()
	p.Network.Mode = policy.NetAllowlist
	p.Network.Allow = []string{"example.com"}
	work := t.TempDir()
	if _, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}, WorkDir: work}); err == nil {
		t.Fatal("allowlist without a proxy port must fail closed")
	}
	argv, how, err := build(p, Spec{Command: []string{"/usr/bin/true", "-x"}, WorkDir: work, ProxyPort: 9})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(argv[0]) != "sandbox-exec" || argv[1] != "-f" || argv[len(argv)-2] != "/usr/bin/true" {
		t.Fatalf("argv = %v", argv)
	}
	prof, err := os.ReadFile(argv[2])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prof), `"localhost:9"`) {
		t.Fatalf("profile: %s", prof)
	}
	if !contains(argv, "TMPDIR="+filepath.Join(work, "tmp")) {
		t.Fatalf("private TMPDIR missing: %v", argv)
	}
	if !strings.Contains(how, "proxy only") {
		t.Fatalf("how = %q", how)
	}
}
