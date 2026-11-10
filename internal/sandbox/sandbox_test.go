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
	skipWindows(t, "symlinks and extension-less executables")
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
	argv, how, _, err := build(p, Spec{Command: []string{"srv", "--flag"}, Env: map[string]string{"HTTP_PROXY": "http://127.0.0.1:1"}})
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
	argv, how, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}})
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
	argv, _, _, _ = build(p, Spec{Command: []string{"/usr/bin/true"}})
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
	if _, _, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}}); err == nil {
		t.Fatal("allowlist without egress relay must fail")
	}

	eg := &Egress{Dir: "/tmp/relay", Exe: "/x/mcp-jail", Allow: p.Network.Allow, UID: 1001, GID: 1002, ResolvConf: "/tmp/relay/resolv.conf"}
	argv, how, _, err := build(p, Spec{Command: []string{"/usr/bin/true", "-x"}, Egress: eg, Env: map[string]string{"HTTPS_PROXY": "http://127.0.0.1:3128"}})
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
	skipWindows(t, "sandbox-exec profiles are built from Unix paths")
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
	if _, _, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}, WorkDir: work}); err == nil {
		t.Fatal("allowlist without a proxy port must fail closed")
	}
	argv, how, _, err := build(p, Spec{Command: []string{"/usr/bin/true", "-x"}, WorkDir: work, ProxyPort: 9})
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

func TestTooBroadAndToolchainBind(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // what os.UserHomeDir reads on Windows
	for _, d := range []string{"home/bin", "home/.local/bin", "home/.config/mcp-jail/run", "home/projects/x", "opt/tool/bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	protect := []string{filepath.Join(home, ".config/mcp-jail/locks"), filepath.Join(home, ".config/mcp-jail/run"), filepath.Join(home, "projects/x/policy.yml")}
	cases := map[string]string{
		"/":                                     "root",
		home:                                    "home",
		root:                                    "home", // a parent of home
		filepath.Join(home, ".config"):          "contains mcp-jail state",
		filepath.Join(home, "projects/x"):       "contains mcp-jail state",
		filepath.Join(home, "projects/x/sub"):   "",
		filepath.Join(home, "projects"):         "contains mcp-jail state",
		filepath.Join(root, "opt/tool"):         "",
		filepath.Join(home, ".local/bin"):       "",
		filepath.Join(home, ".config/mcp-jail"): "contains mcp-jail state",
	}
	for dir, want := range cases {
		if got := tooBroad(dir, protect); got != want {
			t.Errorf("tooBroad(%s) = %q, want %q", dir, got, want)
		}
	}

	skipWindows(t, "toolchainBind looks the binary up in PATH, which needs an extension on Windows")
	// ~/bin/foo: the prefix would be ~ itself; fall back to ~/bin
	exe := filepath.Join(home, "bin", "foo")
	writeExec(t, exe)
	if dir, note := toolchainBind(exe, protect); dir != filepath.Join(home, "bin") || note != "" {
		t.Errorf("~/bin/foo: %q %q", dir, note)
	}
	// ~/.local/bin/uvx: prefix ~/.local is fine (no state under it here)
	exe = filepath.Join(home, ".local", "bin", "uvx")
	writeExec(t, exe)
	if dir, note := toolchainBind(exe, protect); dir != filepath.Join(home, ".local") || note != "" {
		t.Errorf("~/.local/bin/uvx: %q %q", dir, note)
	}
	// a binary directly in $HOME: nothing safe to share
	exe = filepath.Join(home, "server")
	writeExec(t, exe)
	if dir, note := toolchainBind(exe, protect); dir != "" || !strings.Contains(note, "home") {
		t.Errorf("~/server: %q %q", dir, note)
	}
	// /opt/tool/bin/x: unchanged behaviour
	exe = filepath.Join(root, "opt/tool/bin/x")
	writeExec(t, exe)
	if dir, note := toolchainBind(exe, protect); dir != filepath.Join(root, "opt/tool") || note != "" {
		t.Errorf("/opt/tool/bin/x: %q %q", dir, note)
	}
}

func TestMasks(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	mk := func(rel string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(p, 0o750); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pol := mk("proj/policy.yml")
	audit := mk("proj/logs/a.jsonl")
	locks := mk("home/.config/mcp-jail/locks/")
	run := mk("home/.config/mcp-jail/run/")
	missing := filepath.Join(root, "nope")
	got := masks([]string{pol, audit, locks, run, missing, ""}, []string{filepath.Join(root, "proj"), filepath.Join(root, "home/.config")})
	want := []mask{{pol, false}, {audit, false}, {locks, true}, {run, true}}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mask %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if m := masks([]string{pol, locks}, []string{filepath.Join(root, "elsewhere")}); len(m) != 0 {
		t.Errorf("nothing bound, nothing to mask: %+v", m)
	}
}

func TestDarwinProfileProtectsState(t *testing.T) {
	skipWindows(t, "sandbox-exec profiles are built from Unix paths")
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	home := filepath.Join(root, "home")
	run := filepath.Join(home, ".config/mcp-jail/run")
	if err := os.MkdirAll(run, 0o750); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(home, "policy.yml")
	p := policy.Default()
	p.Name = "evil\n(allow default)"
	p.Network.Mode = policy.NetAll
	p.Filesystem.ReadWrite = []string{home}
	prof := darwinProfile(p, Spec{}, profilePaths{home: home, protect: []string{pol, run, ""}})
	tail := prof[strings.LastIndex(prof, "(allow "):]
	for _, want := range []string{`(deny file* (subpath "` + pol + `") (subpath "` + run + `"))`, `(deny network* (subpath "` + pol + `") (subpath "` + run + `"))`} {
		if !strings.Contains(tail, want) {
			t.Errorf("state deny must come after every allow:\n%s", prof)
		}
	}
	if n := strings.Count("\n"+prof, "\n(allow default)\n"); n != 1 {
		t.Errorf("name injected a rule (%d allow default lines):\n%s", n, prof)
	}
	if !strings.Contains(prof, `policy "evil?(allow default)"`) {
		t.Errorf("control character not neutralised:\n%s", prof)
	}
}

func TestBuildLinuxDoesNotShareHomeAsCwd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	bin := t.TempDir()
	writeExec(t, filepath.Join(bin, "bwrap"))
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(home)
	pol := filepath.Join(home, "p.yml")
	if err := os.WriteFile(pol, []byte("name: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	protect := []string{pol, filepath.Join(home, ".config/mcp-jail/locks")}

	// cwd is $HOME and the policy does not list it: not shared
	p := policy.Default()
	argv, how, _, err := build(p, Spec{Command: []string{"/usr/bin/true"}, Protect: protect})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "--ro-bind "+home+" "+home) || !strings.Contains(joined, "--chdir /") {
		t.Errorf("home shared as cwd: %s", joined)
	}
	if !strings.Contains(how, "cwd not shared (home)") {
		t.Errorf("how = %q", how)
	}

	// the policy lists $HOME read-only on purpose: shared, but the policy
	// file inside it is masked
	p.Filesystem.ReadOnly = []string{home}
	argv, how, _, err = build(p, Spec{Command: []string{"/usr/bin/true"}, Protect: protect})
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(argv, " ")
	if !strings.Contains(joined, "--ro-bind "+home+" "+home) || !strings.Contains(joined, "--ro-bind /dev/null "+pol) {
		t.Errorf("explicit read_only home must be bound with the policy file masked: %s", joined)
	}
	if strings.Contains(how, "cwd not shared") {
		t.Errorf("how = %q", how)
	}
}

// sandbox.env: a bare NAME copies the host's value, NAME=value sets one, and
// the update-check / telemetry opt-outs come first unless overridden.
func TestPassthroughEnvSetsAndHardens(t *testing.T) {
	t.Setenv("MCPJ_T", "host")
	got := passthroughEnv([]string{"MCPJ_T", "MCPJ_UNSET", "FOO=bar=baz", "DO_NOT_TRACK=0"})
	want := []string{"DO_NOT_TRACK=0", "NO_UPDATE_NOTIFIER=1", "npm_config_update_notifier=false", "MCPJ_T=host", "FOO=bar=baz"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// skipWindows skips a test of the bubblewrap or sandbox-exec path, which
// works with Unix paths, symlinks and shell scripts.
func skipWindows(t *testing.T, why string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip(why)
	}
}
