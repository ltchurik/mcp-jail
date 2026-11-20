package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/ltchurik/mcp-jail/internal/policy"
)

func TestBuildWindowsArgv(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir()) // masks resolve symlinks (macOS /var)
	ro, rw := filepath.Join(root, "ro"), filepath.Join(root, "rw")
	for _, d := range []string{ro, rw} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	pol := filepath.Join(ro, "policy.yml") // mcp-jail's own file inside a granted dir: denied
	if err := os.WriteFile(pol, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := policy.Default()
	p.Name = "fs server/1"
	p.Network.Mode = policy.NetNone
	p.Filesystem.ReadOnly = []string{ro}
	p.Filesystem.ReadWrite = []string{rw}
	p.Sandbox.Env = []string{"PATH", "FOO=bar"}
	argv, how, dir, err := buildWindows(p, Spec{Command: []string{"srv", "--x"}, Env: map[string]string{"B": "2", "A": "1"}, Protect: []string{pol}})
	if err != nil {
		t.Fatal(err)
	}
	if dir != "" || argv[1] != AppContainerCommand {
		t.Fatalf("argv = %v, dir = %q", argv, dir)
	}
	joined := strings.Join(argv[1:], " ")
	for _, want := range []string{
		"--profile " + profileName(p.Name), "--net none", "--ro " + ro, "--rw " + rw, "--deny " + pol,
		"--env PATH --env FOO=bar", "--set A=1 --set B=2", "-- srv --x",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if !strings.HasSuffix(joined, "-- srv --x") {
		t.Errorf("command must come last: %s", joined)
	}
	if cwd, _ := os.Getwd(); tooBroad(cwd, nil) == "" && !strings.Contains(joined, "--cwd "+cwd) {
		t.Errorf("cwd not shared: %s", joined)
	}
	if !strings.HasPrefix(how, "appcontainer: mcp-jail-fs-server-1-") || !strings.Contains(how, "no network") {
		t.Errorf("how = %q", how)
	}

	p.Network.Mode = policy.NetAll
	argv, how, _, err = buildWindows(p, Spec{Command: []string{"srv"}})
	if err != nil || !contains(argv, "all") || !strings.Contains(how, "network all") {
		t.Errorf("network all: %v %q %v", argv, how, err)
	}
	p.Network.Mode = policy.NetAllowlist
	if _, _, _, err := buildWindows(p, Spec{Command: []string{"srv"}}); err == nil || !strings.Contains(err.Error(), "allowlist cannot be enforced under AppContainer") {
		t.Errorf("allowlist must be refused: %v", err)
	}
	p.Network.Mode = policy.NetNone
	p.Exec.Allow = []string{filepath.Join(root, "bin", "srv")}
	if _, _, _, err := buildWindows(p, Spec{Command: []string{"srv"}}); err == nil || !strings.Contains(err.Error(), "exec.allow cannot be enforced") {
		t.Errorf("exec.allow must be refused: %v", err)
	}
}

func TestBuildWindowsPlain(t *testing.T) {
	p := policy.Default()
	p.Sandbox.Env = []string{"PATH"}
	argv, how, _, err := buildWindowsPlain(p, Spec{Command: []string{"srv", "a"}, Env: map[string]string{"HTTP_PROXY": "http://127.0.0.1:1"}}, "sandbox disabled by policy")
	if err != nil || how != "sandbox disabled by policy" {
		t.Fatal(err, how)
	}
	joined := strings.Join(argv[1:], " ")
	if !strings.HasPrefix(joined, AppContainerCommand+" --plain --env PATH --set HTTP_PROXY=http://127.0.0.1:1 -- srv a") || strings.Contains(joined, "--profile") {
		t.Errorf("plain argv: %s", joined)
	}
}

func TestProfileName(t *testing.T) {
	a, b := profileName("fs"), profileName("fs")
	if a != b || !strings.HasPrefix(a, "mcp-jail-fs-") || len(a) != len("mcp-jail-fs-")+8 {
		t.Errorf("profileName(fs) = %q", a)
	}
	if profileName("fs") == profileName("fs2") {
		t.Error("different policies must not share a profile")
	}
	long := profileName(strings.Repeat("ä/b ", 60))
	if len(long) > 64 || strings.ContainsAny(long, "ä/ ") {
		t.Errorf("long name: %q", long)
	}
}

func TestExplainAppContainerElsewhere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows the backend is the native one")
	}
	p := policy.Default()
	p.Sandbox.Backend = policy.BackendAppContainer
	plan := Explain(p, Spec{Command: []string{"srv"}})
	if plan.Kind != "appcontainer" || !strings.Contains(strings.Join(plan.Notes, "\n"), "needs Windows") {
		t.Fatalf("plan: %+v", plan)
	}
	if _, _, _, err := build(p, Spec{Command: []string{"srv"}}); err == nil || !strings.Contains(err.Error(), "needs Windows") {
		t.Fatalf("build must refuse: %v", err)
	}
}

func TestCapabilitySID(t *testing.T) {
	// values Windows itself put on C:\, C:\Users and a profile (seen with icacls)
	want := map[string]string{
		"isolatedWin32-volumeRootMinimal":   "S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176",
		"isolatedWin32-profilesRootMinimal": "S-1-15-3-65536-4045685566-1323397456-4055816110-285687253-194181-4019357623-1925838800-191844675",
		"isolatedWin32-userProfileMinimal":  "S-1-15-3-65536-599108337-2355189375-1353122160-3480128286-3345335107-485756383-4087318168-230526575",
	}
	if len(ancestorCapabilities) != len(want) {
		t.Fatalf("ancestorCapabilities = %v", ancestorCapabilities)
	}
	for _, name := range ancestorCapabilities {
		if got := capabilitySID(name); got != want[name] {
			t.Errorf("%s: %s, want %s", name, got, want[name])
		}
	}
}

func TestStatAncestors(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "me")
	if runtime.GOOS == "windows" {
		home = `C:\Users\me`
	}
	proj := filepath.Join(home, "projects", "webshop")
	tmp := filepath.Join(home, "AppData", "Local", "Temp", "x", "srv")
	inside := filepath.Join(proj, "src") // under another share: nothing to add
	got := statAncestors([]string{proj, tmp, inside}, home)
	want := []string{
		filepath.Join(home, "AppData"), filepath.Join(home, "AppData", "Local"), filepath.Join(home, "AppData", "Local", "Temp"),
		filepath.Join(home, "AppData", "Local", "Temp", "x"), filepath.Join(home, "projects"),
	}
	want = append(want, home)
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v\nwant %v", got, want)
	}
	// outside the profile: up to, not including, the volume root
	other := filepath.Join(string(filepath.Separator), "work", "a", "b")
	if runtime.GOOS == "windows" {
		other = `D:\work\a\b`
	}
	got = statAncestors([]string{other}, home)
	if want := []string{filepath.Dir(filepath.Dir(other)), filepath.Dir(other)}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v\nwant %v", got, want)
	}
}
